drop function if exists "public"."get_messages"(p_team_id uuid, p_limit integer, p_offset integer);

drop index if exists "public"."idx_messages_team_id_created_at";

CREATE INDEX idx_messages_pagination ON public.messages USING btree (team_id, created_at DESC, id DESC);

CREATE INDEX idx_snippets_team_url_path ON public.code_snippets USING btree (team_id, remote_url, file_path);

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.get_code_discussions(p_team_id uuid, p_remote_url text, p_file_path text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$declare
    v_user_id uuid := auth.uid();
    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;
    v_result jsonb;
begin
    --------------------------------------------------------------------
    -- 1. Security Gates
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object('status', 'error', 'message', 'Unauthenticated');
    end if;

    if not exists (
        select 1 from team_members 
        where team_id = p_team_id and user_id = v_user_id
    ) then
        return jsonb_build_object('status', 'error', 'message', 'Forbidden');
    end if;

    --------------------------------------------------------------------
    -- 2. Decryption Logic
    --------------------------------------------------------------------
    select encrypted_data_key into v_enc_dk
    from team_data_keys where team_id = p_team_id;

    if v_enc_dk is null then
        return jsonb_build_object('status', 'error', 'message', 'Key missing');
    end if;

    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    v_data_key := pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);

    --------------------------------------------------------------------
    -- 3. Fetching Only Essential Discussion Data
    --------------------------------------------------------------------
    select coalesce(jsonb_agg(
        jsonb_build_object(
            -- 1. Code Snippet Fields
            'id', s.id,
            'start_line', s.start_line,
            'end_line', s.end_line,
            'content', convert_from(
                extensions.pgp_sym_decrypt_bytea(
                    s.snippet_ciphertext, 
                    encode(v_data_key, 'base64')
                ), 
                'utf8'
            ),
            'ref', s.ref,
            'remote_url', s.remote_url,
            'file_path', s.file_path,
            'commit_sha', s.commit_sha,
            'created_at', s.created_at,

            -- 2. Nested Parent Message Details
            'message', jsonb_build_object(
                'message_id', m.id,
                'content', convert_from(
                    extensions.pgp_sym_decrypt_bytea(
                        m.content_ciphertext,
                        encode(v_data_key, 'base64')
                    ),
                    'utf8'
                ),
                -- 3. Nested User Details (Inside the Message)
                'u', jsonb_build_object(
                    'user_id', m.user_id,
                    'avatar_url', u.raw_user_meta_data ->> 'avatar_url',
                    'display_name', u.raw_user_meta_data ->> 'display_name',
                    'username', u.raw_user_meta_data ->> 'username'
                )
            )
        ) ORDER BY s.created_at DESC
    ), '[]'::jsonb)
    into v_result
    from public.code_snippets s
    join public.messages m on m.id = s.message_id
    join auth.users u on u.id = m.user_id
    where s.team_id = p_team_id
      and s.remote_url = p_remote_url
      and s.file_path = p_file_path;

    return jsonb_build_object(
        'status', 'success',
        'discussions', v_result
    );
end;$function$
;

CREATE OR REPLACE FUNCTION public.get_messages(p_team_id uuid, p_limit integer, p_anchor_id uuid DEFAULT NULL::uuid, p_direction text DEFAULT 'before'::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions', 'vault'
AS $function$

declare
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
                            'content', convert_from(extensions.pgp_sym_decrypt_bytea(s.snippet_ciphertext, encode(v_data_key, 'base64')), 'utf8')
                        ) ORDER BY s.created_at ASC
                    ), '[]'::jsonb)
                    from public.code_snippets s where s.message_id = m_filtered.id
                ),
                'created_at', m_filtered.created_at,
                'u', jsonb_build_object(
                    'user_id', m_filtered.user_id,
                    'avatar_url', u.raw_user_meta_data ->> 'avatar_url',
                    'display_name', u.raw_user_meta_data ->> 'display_name',
                    'username', u.raw_user_meta_data ->> 'username'
                )
            ) as msg_obj
        from (
            -- Sub-query handles the high-performance directional seek
            select id, created_at, user_id, content_ciphertext, parent_id, thread_id
            from (
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id
                    from messages
                    where team_id = p_team_id
                      and p_direction IN ('before', 'around')
                      and (v_anchor_ts is null or (created_at, id) < (v_anchor_ts, p_anchor_id))
                    order by created_at DESC, id DESC
                    limit p_limit
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id
                    from messages
                    where id = p_anchor_id and p_direction = 'around'
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id
                    from messages
                    where team_id = p_team_id
                      and p_direction IN ('after', 'around')
                      and v_anchor_ts is not null 
                      and (created_at, id) > (v_anchor_ts, p_anchor_id)
                    order by created_at ASC, id ASC
                    limit p_limit
                )
            ) m_union
            group by id, created_at, user_id, content_ciphertext, parent_id, thread_id
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
end;
$function$
;


