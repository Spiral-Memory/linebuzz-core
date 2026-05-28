CREATE OR REPLACE FUNCTION public.insert_slack_message (
  p_team_id         uuid,
  p_content         text,
  p_source_metadata jsonb,
  p_quoted_id       uuid DEFAULT NULL::uuid,
  p_parent_id       uuid DEFAULT NULL::uuid
)
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

GRANT ALL ON FUNCTION public.insert_slack_message(uuid, text, jsonb, uuid, uuid) TO anon;

GRANT ALL ON FUNCTION public.insert_slack_message(uuid, text, jsonb, uuid, uuid) TO authenticated;

GRANT ALL ON FUNCTION public.insert_slack_message(uuid, text, jsonb, uuid, uuid) TO service_role;