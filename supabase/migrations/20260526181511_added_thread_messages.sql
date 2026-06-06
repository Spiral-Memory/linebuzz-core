SET check_function_bodies = false;
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
    -- 4. Get Total Count (top-level only)
    --------------------------------------------------------------------
    select count(*)
    into v_total_count
    from messages
    where team_id = p_team_id
      and parent_id is null;

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
                        'source', qm.source,
                        'source_metadata', qm.source_metadata,
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
                'reply_count', (
                    select count(*)
                    from messages r
                    where r.parent_id = m_filtered.id
                ),
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
            -- Sub-query handles the high-performance directional seek (top-level messages only)
            select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
            from (
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where team_id = p_team_id
                      and parent_id is null
                      and p_direction IN ('before', 'around')
                      and (v_anchor_ts is null or (created_at, id) < (v_anchor_ts, p_anchor_id))
                    order by created_at DESC, id DESC
                    limit p_limit
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where id = p_anchor_id
                      and parent_id is null
                      and p_direction = 'around'
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where team_id = p_team_id
                      and parent_id is null
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
CREATE FUNCTION public.get_thread_messages(p_team_id uuid, p_thread_id uuid, p_limit integer, p_anchor_id uuid DEFAULT NULL::uuid, p_direction text DEFAULT 'before'::text)
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
    -- 5. Get Total Count (replies to this thread only)
    --------------------------------------------------------------------
    select count(*)
    into v_total_count
    from messages
    where team_id = p_team_id
      and parent_id = p_thread_id;

    --------------------------------------------------------------------
    -- 6. Fetch + Decrypt Thread Messages (Unified Directional Query)
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
                        'source', qm.source,
                        'source_metadata', qm.source_metadata,
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
            -- Sub-query handles the high-performance directional seek (thread replies only)
            select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
            from (
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where team_id = p_team_id
                      and parent_id = p_thread_id
                      and p_direction IN ('before', 'around')
                      and (v_anchor_ts is null or (created_at, id) < (v_anchor_ts, p_anchor_id))
                    order by created_at DESC, id DESC
                    limit p_limit
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where id = p_anchor_id
                      and parent_id = p_thread_id
                      and p_direction = 'around'
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id, source, source_metadata
                    from messages
                    where team_id = p_team_id
                      and parent_id = p_thread_id
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
    -- 7. Wrap inside success JSONB
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
