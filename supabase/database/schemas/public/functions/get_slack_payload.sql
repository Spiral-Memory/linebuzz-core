CREATE FUNCTION public.get_slack_payload (
  p_message_id uuid
)
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

    -- Thread/parent variables
    v_parent_id uuid;
    v_parent_slack_ts text;

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
        m.parent_id,
        ti.access_token, 
        ti.settings->>'active_channel_id'
    into 
        v_team_id, 
        v_user_id, 
        v_msg_ciphertext, 
        v_quoted_id,
        v_parent_id,
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
    -- 2b. Resolve Parent Thread Timestamp (for Slack threading)
    --------------------------------------------------------------------
    if v_parent_id is not null then
        select source_metadata->>'slack_event_ts'
        into v_parent_slack_ts
        from public.messages
        where id = v_parent_id;
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
            'parent_slack_ts', v_parent_slack_ts,
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

GRANT ALL ON FUNCTION public.get_slack_payload(uuid) TO anon;

GRANT ALL ON FUNCTION public.get_slack_payload(uuid) TO authenticated;

GRANT ALL ON FUNCTION public.get_slack_payload(uuid) TO service_role;