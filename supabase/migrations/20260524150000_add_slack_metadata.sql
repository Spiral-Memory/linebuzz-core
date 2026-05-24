-- 1. Include source and source_metadata in the messages table with default source as 'app'
ALTER TABLE "public"."messages" ADD COLUMN IF NOT EXISTS "source" text DEFAULT 'app';
ALTER TABLE "public"."messages" ADD COLUMN IF NOT EXISTS "source_metadata" jsonb;

-- 2. Create the insert_slack_message database function (callable only by service_role)
CREATE OR REPLACE FUNCTION public.insert_slack_message(
    p_team_id uuid, 
    p_content text, 
    p_source_metadata jsonb
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

    v_thread_id := gen_random_uuid();

    --------------------------------------------------------------------
    -- Insert message with source = 'slack' and metadata
    --------------------------------------------------------------------
    insert into messages (
        team_id,
        user_id,
        thread_id,
        content_ciphertext,
        content_hash,
        source,
        source_metadata
    ) values (
        p_team_id,
        v_user_id,
        v_thread_id,
        v_cipher,
        v_hash,
        'slack',
        p_source_metadata
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
            'parent_id', null,
            'content', p_content,
            'created_at', v_created_at,
            'attachments', '[]'::jsonb,
            'source', 'slack',
            'source_metadata', p_source_metadata,
            'u', jsonb_build_object(
                'user_id', v_user_id,
                'username', p_source_metadata ->> 'username',
                'display_name', p_source_metadata ->> 'display_name',
                'avatar_url', p_source_metadata ->> 'avatar_url'
            )
        )
    );
end;$function$;

-- 3. Recreate install_slack to add slack bot user as team member on success
CREATE OR REPLACE FUNCTION public.install_slack(p_state uuid, p_access_token text, p_channels jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal', 'extensions', 'vault'
AS $function$
declare
    -- Retrieved user details from oauth_state
    v_owner_id uuid;
    v_team_id uuid;
    v_role text;
    v_bot_id uuid;
    
    -- Encryption Variables
    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;
    v_encrypted_token bytea;
begin
    --------------------------------------------------------------------
    -- 1. State Verification
    --------------------------------------------------------------------
    delete from public.integration_oauth_states
    where id = p_state 
      and provider = 'slack' 
      and expires_at > now()
    returning team_id, user_id into v_team_id, v_owner_id;

    if not found then
        return jsonb_build_object(
            'status', 'error',
            'code', 'INVALID_STATE',
            'message', 'The Slack session has expired or is invalid.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. Membership Check
    --------------------------------------------------------------------
    select role into v_role
    from public.team_members
    where team_id = v_team_id and user_id = v_owner_id;

    if v_role != 'admin' or v_role is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'Initiating user is no longer an admin.'
        );
    end if;

    --------------------------------------------------------------------
    -- 3. Encryption Setup
    --------------------------------------------------------------------
    select encrypted_data_key into v_enc_dk
    from public.team_data_keys
    where team_id = v_team_id;

    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    if v_enc_dk is null or v_master_key is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'CONFIG_ERROR',
            'message', 'Team encryption configuration missing.'
        );
    end if;

    v_data_key := extensions.pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);
    v_encrypted_token := extensions.pgp_sym_encrypt_bytea(
        p_access_token::bytea, 
        encode(v_data_key, 'base64')
    );

    --------------------------------------------------------------------
    -- 4. Upsert Integration Record
    --------------------------------------------------------------------
    insert into public.team_integrations (
        team_id, 
        provider, 
        access_token, 
        settings
    )
    values (
        v_team_id,
        'slack',
        v_encrypted_token,
        jsonb_build_object(
            'channels', p_channels,
            'active_channel_id', null
        )
    )
    on conflict (team_id, provider) 
    do update set 
        access_token = excluded.access_token,
        settings = excluded.settings,
        updated_at = now();

    --------------------------------------------------------------------
    -- 5. Add Slack Bot user as team member dynamically
    --------------------------------------------------------------------
    select value::uuid into v_bot_id from internal.app_settings where key = 'slack_bot_id';
    
    if v_bot_id is not null then
        insert into public.team_members (team_id, user_id, role)
        values (v_team_id, v_bot_id, 'member')
        on conflict (team_id, user_id) do nothing;
    end if;

    --------------------------------------------------------------------
    -- 6. Return Success
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'SLACK_CONNECTED',
        'team_id', v_team_id,
        'message', 'Slack integration successfully completed.'
    );
end;$function$;

-- 4. Recreate disconnect_slack to remove slack bot user from team members
CREATE OR REPLACE FUNCTION public.disconnect_slack(p_team_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal'
AS $function$
declare
    v_user_id uuid := auth.uid();
    v_role text;
    v_bot_id uuid;
begin
    --------------------------------------------------------------------
    -- 1. Check Authentication
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. Verify Admin Permissions
    --------------------------------------------------------------------
    select role into v_role 
    from public.team_members 
    where team_id = p_team_id and user_id = v_user_id;

    if v_role != 'admin' or v_role is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'Admin permissions required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 3. Delete Integration & Remove Slack Bot user from team members
    --------------------------------------------------------------------
    delete from public.team_integrations
    where team_id = p_team_id and provider = 'slack';

    select value::uuid into v_bot_id from internal.app_settings where key = 'slack_bot_id';
    
    if v_bot_id is not null then
        delete from public.team_members
        where team_id = p_team_id and user_id = v_bot_id;
    end if;

    --------------------------------------------------------------------
    -- 4. Return Success
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'DISCONNECTED',
        'message', 'Slack integration removed successfully.'
    );
end;$function$;

-- 5. Recreate get_message_by_id to include source and source_metadata
CREATE OR REPLACE FUNCTION public.get_message_by_id(p_team_id uuid, p_message_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
AS $function$declare
    v_user_id uuid := auth.uid();

    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;

    v_row jsonb;
begin
    --------------------------------------------------------------------
    -- 1. auth check
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. membership check
    --------------------------------------------------------------------
    if not exists (
        select 1
        from team_members
        where team_id = p_team_id
          and user_id = v_user_id
    ) then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'User is not a member of this team.'
        );
    end if;

    --------------------------------------------------------------------
    -- 3. load team encrypted data key
    --------------------------------------------------------------------
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

    select decrypted_secret
    into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    if v_master_key is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'MISSING_MASTER_KEY',
            'message', 'Master key not available.'
        );
    end if;

    -- decrypt team data key
    v_data_key := pgp_sym_decrypt_bytea(
        v_enc_dk,
        v_master_key
    );

    --------------------------------------------------------------------
    -- 4. fetch + decrypt single message
    --------------------------------------------------------------------
    select jsonb_build_object(
        'message_id', m.id,
        'parent_id', m.parent_id,
        'thread_id', m.thread_id,
        'quoted_id', m.quoted_id,
        'quoted_message', (
            select jsonb_build_object(
                'content', convert_from(
                    pgp_sym_decrypt_bytea(
                        qm.content_ciphertext,
                        encode(v_data_key, 'base64')
                    ),
                    'utf8'
                ),
                'u', jsonb_build_object(
                    'user_id', qu.id,
                    'avatar_url', qu.raw_user_meta_data ->> 'avatar_url',
                    'display_name', qu.raw_user_meta_data ->> 'display_name',
                    'username', qu.raw_user_meta_data ->> 'username'
                )
            )
            from messages qm
            join auth.users qu on qu.id = qm.user_id
            where qm.id = m.quoted_id
        ),
        'content', convert_from(
            pgp_sym_decrypt_bytea(
                m.content_ciphertext,
                encode(v_data_key, 'base64')
            ),
            'utf8'
        ),
        'attachments', (
            select coalesce(jsonb_agg(
                jsonb_build_object(
                    'id', s.id,
                    'type', 'code',
                    'remote_url', s.remote_url,
                    'ref', s.ref,
                    'commit_sha', s.commit_sha,
                    'file_path', s.file_path,
                    'start_line', s.start_line,
                    'end_line', s.end_line,
                    'content', convert_from(extensions.pgp_sym_decrypt_bytea(s.snippet_ciphertext, encode(v_data_key, 'base64')), 'utf8'),
                    'patch', convert_from(extensions.pgp_sym_decrypt_bytea(s.patch, encode(v_data_key, 'base64')), 'utf8')
                ) ORDER BY s.created_at ASC
            ), '[]'::jsonb)
            from public.code_snippets s
            where s.message_id = m.id
            ),
        'created_at', m.created_at,
        'source', m.source,
        'source_metadata', m.source_metadata,
        'u', jsonb_build_object(
            'user_id', m.user_id,
            'avatar_url', u.raw_user_meta_data ->> 'avatar_url',
            'display_name', u.raw_user_meta_data ->> 'display_name',
            'username', u.raw_user_meta_data ->> 'username'
        )
    )
    into v_row
    from messages m
    join auth.users u on u.id = m.user_id
    where m.id = p_message_id
      and m.team_id = p_team_id;

    if v_row is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'NOT_FOUND',
            'message', 'Message not found.'
        );
    end if;

    --------------------------------------------------------------------
    -- 5. wrap success
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGE_LOADED',
        'team_id', p_team_id,
        'message', v_row
    );
end;$function$;

-- 6. Recreate get_messages to include source and source_metadata
CREATE OR REPLACE FUNCTION public.get_messages(p_team_id uuid, p_limit integer, p_anchor_id uuid DEFAULT NULL::uuid, p_direction text DEFAULT 'before'::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions', 'vault'
AS $function$declare
    v_user_id uuid := auth.uid();

    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;

    v_rows jsonb := '[]'::jsonb;
    v_total_count int := 0; 
    v_anchor_ts timestamptz;
begin
    --------------------------------------------------------------------
    -- 1. auth check
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. membership check
    --------------------------------------------------------------------
    if not exists (
        select 1 from team_members
        where team_id = p_team_id
        and user_id = v_user_id
    ) then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'User is not a member of this team.'
        );
    end if;

    --------------------------------------------------------------------
    -- 3. Resolve Anchor Coordinates
    --------------------------------------------------------------------
    if p_anchor_id is not null then
        select created_at into v_anchor_ts 
        from messages 
        where id = p_anchor_id and team_id = p_team_id;
    end if;

    --------------------------------------------------------------------
    -- 4. load team's encrypted data key
    --------------------------------------------------------------------
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

    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    -- decrypt team data key
    v_data_key := pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);

    --------------------------------------------------------------------
    -- 4. Get Total Count
    --------------------------------------------------------------------
    select count(*)
    into v_total_count
    from messages
    where team_id = p_team_id;

    --------------------------------------------------------------------
    -- 5. Fetch + Decrypt Messages (Unified Directional Query)
    --------------------------------------------------------------------
    select jsonb_agg(sub_final.msg_obj order by sub_final.created_at ASC)
    into v_rows
    from (
        select 
            m_filtered.created_at,
            jsonb_build_object(
                'message_id', m_filtered.id,
                'quoted_id', m_filtered.quoted_id,
                'quoted_message', (
                    select jsonb_build_object(
                        'content', convert_from(
                            extensions.pgp_sym_decrypt_bytea(
                                qm.content_ciphertext,
                                encode(v_data_key, 'base64')
                            ),
                            'utf8'
                        ),
                        'u', jsonb_build_object(
                            'user_id', qu.id,
                            'avatar_url', qu.raw_user_meta_data ->> 'avatar_url',
                            'display_name', qu.raw_user_meta_data ->> 'display_name',
                            'username', qu.raw_user_meta_data ->> 'username'
                        )
                    )
                    from messages qm
                    join auth.users qu on qu.id = qm.user_id
                    where qm.id = m_filtered.quoted_id
                ),
                'parent_id', m_filtered.parent_id,
                'thread_id', m_filtered.thread_id,
                'content', case 
                    when m_filtered.content_ciphertext is not null 
                    then convert_from(extensions.pgp_sym_decrypt_bytea(m_filtered.content_ciphertext, encode(v_data_key, 'base64')), 'utf8')
                    else null 
                end,
                'attachments', (
                    select coalesce(jsonb_agg(
                        jsonb_build_object(
                            'id', s.id, 
                            'type', 'code',
                            'remote_url', s.remote_url,
                            'ref', s.ref,
                            'commit_sha', s.commit_sha,
                            'file_path', s.file_path,
                            'start_line', s.start_line,
                            'end_line', s.end_line,
                            'content', convert_from(extensions.pgp_sym_decrypt_bytea(s.snippet_ciphertext, encode(v_data_key, 'base64')), 'utf8'),
                            'patch', convert_from(extensions.pgp_sym_decrypt_bytea(s.patch, encode(v_data_key, 'base64')), 'utf8')
                        ) ORDER BY s.created_at ASC
                    ), '[]'::jsonb)
                    from public.code_snippets s where s.message_id = m_filtered.id
                ),
                'created_at', m_filtered.created_at,
                'source', m_filtered.source,
                'source_metadata', m_filtered.source_metadata,
                'u', jsonb_build_object(
                    'user_id', m_filtered.user_id,
                    'avatar_url', u.raw_user_meta_data ->> 'avatar_url',
                    'display_name', u.raw_user_meta_data ->> 'display_name',
                    'username', u.raw_user_meta_data ->> 'username'
                )
            ) as msg_obj
        from (
            -- Sub-query handles the high-performance directional seek
            select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
            from (
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where team_id = p_team_id
                      and p_direction IN ('before', 'around')
                      and (v_anchor_ts is null or (created_at, id) < (v_anchor_ts, p_anchor_id))
                    order by created_at DESC, id DESC
                    limit p_limit
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where id = p_anchor_id and p_direction = 'around'
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where team_id = p_team_id
                      and p_direction IN ('after', 'around')
                      and v_anchor_ts is not null 
                      and (created_at, id) > (v_anchor_ts, p_anchor_id)
                    order by created_at ASC, id ASC
                    limit p_limit
                )
            ) m_union
            group by id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
        ) m_filtered
        join auth.users u on u.id = m_filtered.user_id
    ) sub_final;

    --------------------------------------------------------------------
    -- 6. Wrap inside success JSONB
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGES_LOADED',
        'meta', jsonb_build_object(
            'total', v_total_count,
            'limit', p_limit,
            'anchor', p_anchor_id,
            'direction', p_direction,
            'oldest_id', (v_rows->0)->>'message_id',
            'newest_id', (v_rows->-1)->>'message_id'
        ),
        'messages', coalesce(v_rows, '[]'::jsonb)
    );
end;$function$;
