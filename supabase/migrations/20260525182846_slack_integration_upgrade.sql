SET check_function_bodies = false;
DROP FUNCTION public.insert_slack_message(p_team_id uuid, p_content text, p_source_metadata jsonb);
CREATE OR REPLACE FUNCTION public.get_slack_payload(p_message_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal', 'extensions', 'vault'
AS $function$declare
    -- Context Variables
    v_team_id uuid;
    v_user_id uuid;
    v_msg_ciphertext bytea;
    v_token_ciphertext bytea;

    -- Key Variables
    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;

    -- Output Variables
    v_slack_channel_id text;
    v_display_name text;
    v_username text;
    v_avatar_url text;

    -- Quoted message decryption variables
    v_quoted_id uuid;
    v_quoted_ciphertext bytea;
    v_quoted_user_id uuid;
    v_quoted_display_name text;
    v_quoted_username text;
    v_quoted_msg text;
    v_quoted_source text;
    v_quoted_metadata jsonb;

    -- Code snippet decryption variables
    v_code_snippets_json jsonb;
begin
    --------------------------------------------------------------------
    -- 1. Service Role Gate
    --------------------------------------------------------------------
    -- This function must ONLY be called by our trusted Edge Function.
    -- The service_role bypasses RLS, which is necessary to read tokens.
    if auth.role() <> 'service_role' then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'Access denied.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. Resolve Context and Ciphertexts
    --------------------------------------------------------------------
    select 
        m.team_id, 
        m.user_id, 
        m.content_ciphertext, 
        m.quoted_id,
        ti.access_token, 
        ti.settings->>'active_channel_id'
    into 
        v_team_id, 
        v_user_id, 
        v_msg_ciphertext, 
        v_quoted_id,
        v_token_ciphertext, 
        v_slack_channel_id
    from public.messages m
    join public.team_integrations ti on m.team_id = ti.team_id
    where m.id = p_message_id and ti.provider = 'slack';

    if not found then
        return jsonb_build_object(
            'status', 'error', 
            'code', 'NOT_FOUND',
            'message', 'Message or Slack integration not found.'
        );
    end if;

    --------------------------------------------------------------------
    -- 3. Resolve Keys
    --------------------------------------------------------------------
    -- Get the team-specific data key
    select encrypted_data_key into v_enc_dk 
    from public.team_data_keys 
    where team_id = v_team_id;

    -- Get the global master key from Vault
    select decrypted_secret into v_master_key 
    from vault.decrypted_secrets 
    where name = 'app_master_key_latest';

    if v_enc_dk is null or v_master_key is null then
        return jsonb_build_object(
            'status', 'error', 
            'code', 'KEY_ERROR',
            'message', 'Decryption keys unavailable.'
        );
    end if;

    -- Phase 1: Decrypt the Data Key using Master Key
    v_data_key := extensions.pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);

    --------------------------------------------------------------------
    -- 4. User Metadata Lookups
    --------------------------------------------------------------------
    select 
        raw_user_meta_data ->> 'display_name',
        raw_user_meta_data ->> 'username',
        raw_user_meta_data ->> 'avatar_url'
    into 
        v_display_name, 
        v_username,
        v_avatar_url
    from auth.users where id = v_user_id;

    --------------------------------------------------------------------
    -- 4b. Quoted Message Lookup and Decryption
    --------------------------------------------------------------------
    if v_quoted_id is not null then
        select 
            content_ciphertext,
            user_id,
            source,
            source_metadata
        into 
            v_quoted_ciphertext,
            v_quoted_user_id,
            v_quoted_source,
            v_quoted_metadata
        from public.messages
        where id = v_quoted_id;

        if v_quoted_ciphertext is not null then
            v_quoted_msg := convert_from(
                extensions.pgp_sym_decrypt_bytea(v_quoted_ciphertext, encode(v_data_key, 'base64')), 
                'utf8'
            );

            if v_quoted_source = 'slack' and v_quoted_metadata ? 'username' then
                v_quoted_username := v_quoted_metadata ->> 'username';
            else
                select 
                    raw_user_meta_data ->> 'display_name',
                    raw_user_meta_data ->> 'username'
                into 
                    v_quoted_display_name, 
                    v_quoted_username
                from auth.users where id = v_quoted_user_id;
            end if;
        end if;
    end if;

    --------------------------------------------------------------------
    -- 4c. Code Snippets Lookup and Decryption
    --------------------------------------------------------------------
    select 
        coalesce(
            jsonb_agg(
                jsonb_build_object(
                    'file_path', s.file_path,
                    'start_line', s.start_line,
                    'end_line', s.end_line,
                    'remote_url', s.remote_url,
                    'content', convert_from(
                        extensions.pgp_sym_decrypt_bytea(s.snippet_ciphertext, encode(v_data_key, 'base64')), 
                        'utf8'
                    )
                )
            ),
            '[]'::jsonb
        )
    into 
        v_code_snippets_json
    from public.code_snippets s
    where s.message_id = p_message_id;

    --------------------------------------------------------------------
    -- 5. Final Decryption and Assembly
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'payload', jsonb_build_object(
            'channel_id', v_slack_channel_id,
            'user_name', coalesce(v_username, v_display_name, 'Buzz Member'),
            'user_avatar_url', v_avatar_url,
            'quoted_message', case 
                when v_quoted_msg is not null then jsonb_build_object(
                    'user_name', coalesce(v_quoted_username, v_quoted_display_name, 'Buzz Member'),
                    'content', v_quoted_msg
                )
                else null
            end,
            'code_snippets', v_code_snippets_json,
            -- Phase 2: Decrypt the Token and Message using the Data Key
            'decrypted_token', convert_from(
                extensions.pgp_sym_decrypt_bytea(v_token_ciphertext, encode(v_data_key, 'base64')), 
                'utf8'
            ),
            'decrypted_message', convert_from(
                extensions.pgp_sym_decrypt_bytea(v_msg_ciphertext, encode(v_data_key, 'base64')), 
                'utf8'
            )
        )
    );
end;$function$;
CREATE FUNCTION public.insert_slack_message(p_team_id uuid, p_content text, p_source_metadata jsonb, p_quoted_id uuid DEFAULT NULL::uuid, p_parent_id uuid DEFAULT NULL::uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal', 'extensions', 'vault'
AS $function$declare
    v_user_id uuid; -- Resolved dynamically from internal.app_settings
    
    ---Message Info ----
    v_thread_id uuid;
    v_message_id uuid;
    v_created_at timestamptz;
    v_cipher bytea;      -- Final Encrypted Message
    v_hash text;

    v_enc_dk bytea;      -- Encrypted Data Key (from DB)
    v_data_key bytea;    -- Decrypted Data Key (Raw Bytes)
    v_data_key_b64 text; -- Storing data key (Base64) for reuse
    v_master_key text;   -- Master Key (Passphrase from Vault)
begin
    --------------------------------------------------------------------
    -- Authentication check (Only callable by Supabase Edge Functions / service_role)
    --------------------------------------------------------------------
    if auth.role() <> 'service_role' then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'Access denied.'
        );
    end if;

    --------------------------------------------------------------------
    -- Deduplication check using slack_event_id
    --------------------------------------------------------------------
    if p_source_metadata ? 'slack_event_id' then
        if exists (
            select 1 
            from public.messages 
            where team_id = p_team_id 
              and source = 'slack' 
              and source_metadata ->> 'slack_event_id' = p_source_metadata ->> 'slack_event_id'
        ) then
            -- Safely return success indicating it has already been processed to avoid Slack re-sending
            return jsonb_build_object(
                'status', 'success',
                'code', 'MESSAGE_DUPLICATE',
                'message', 'Slack event already processed.'
            );
        end if;
    end if;

    --------------------------------------------------------------------
    -- Fetch dynamically the slack_bot_id
    --------------------------------------------------------------------
    select value::uuid into v_user_id from internal.app_settings where key = 'slack_bot_id';
    
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'CONFIG_ERROR',
            'message', 'Slack bot user ID not configured.'
        );
    end if;

    --------------------------------------------------------------------
    -- Fetch & Decrypt Team Data Key
    --------------------------------------------------------------------
    -- A. Get Master Key from Vault
    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    if v_master_key is null then
        return jsonb_build_object('status', 'error', 'code', 'CONFIG_ERROR', 'message', 'Master key not found in vault.');
    end if;

    -- B. Get Encrypted Team Key
    select encrypted_data_key
    into v_enc_dk
    from team_data_keys
    where team_id = p_team_id;

    if v_enc_dk is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'MISSING_TEAM_KEY',
            'message', 'Team encryption key missing.'
        );
    end if;

    -- C. Decrypt the Team Data Key
    v_data_key := extensions.pgp_sym_decrypt_bytea(
        v_enc_dk, 
        v_master_key
    );
    
    -- Stores data key 64 bit for reuse
    v_data_key_b64 := encode(v_data_key, 'base64');

    --------------------------------------------------------------------
    -- Encrypt the message content
    --------------------------------------------------------------------
    if p_content is not null and length(p_content) > 0 then
        v_cipher := extensions.pgp_sym_encrypt(p_content, v_data_key_b64);
        v_hash:= encode(extensions.digest(p_content, 'sha256'), 'base64');
    else
        v_cipher := null;
        v_hash:= null;
    end if;

    if p_parent_id is not null then
        select coalesce(thread_id, id) into v_thread_id 
        from public.messages 
        where id = p_parent_id;
    end if;

    if v_thread_id is null then
        v_thread_id := gen_random_uuid();
    end if;

    --------------------------------------------------------------------
    -- Insert message with source = 'slack' and metadata
    --------------------------------------------------------------------
    insert into messages (
        team_id,
        user_id,
        thread_id,
        parent_id,
        content_ciphertext,
        content_hash,
        source,
        source_metadata,
        quoted_id
    ) values (
        p_team_id,
        v_user_id,
        v_thread_id,
        p_parent_id,
        v_cipher,
        v_hash,
        'slack',
        p_source_metadata,
        p_quoted_id
    )
    returning id, created_at into v_message_id, v_created_at;

    --------------------------------------------------------------------
    -- Return success JSON
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGE_CREATED',
        'message', jsonb_build_object(
            'message_id', v_message_id,
            'thread_id', v_thread_id,
            'parent_id', p_parent_id,
            'content', p_content,
            'created_at', v_created_at,
            'attachments', '[]'::jsonb,
            'source', 'slack',
            'source_metadata', p_source_metadata,
            'quoted_id', p_quoted_id,
            'u', jsonb_build_object(
                'user_id', v_user_id,
                'username', p_source_metadata ->> 'username',
                'display_name', p_source_metadata ->> 'display_name',
                'avatar_url', p_source_metadata ->> 'avatar_url'
            )
        )
    );
end;$function$;
