alter table "public"."code_snippets" add column "patch" bytea;

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.create_message(p_team_id uuid, p_content text, p_attachments jsonb DEFAULT '[]'::jsonb, p_parent_id uuid DEFAULT NULL::uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions', 'vault'
AS $function$declare
    v_user_id uuid := auth.uid();
    v_avatar_url text;
    v_display_name text;
    v_username text;
    
    ---Message Info ----
    v_thread_id uuid;
    v_message_id uuid;
    v_created_at timestamptz;
    v_parent_is_root boolean;
    v_cipher bytea;      -- Final Encrypted Message
    v_hash text;

    v_enc_dk bytea;      -- Encrypted Data Key (from DB)
    v_data_key bytea;    -- Decrypted Data Key (Raw Bytes)
    v_data_key_b64 text; -- Storing data key (Base64) for reuse
    v_master_key text;   -- Master Key (Passphrase from Vault)
    
    --- AttachmentInfo ---
    v_att record;        -- For looping attachment records
    v_patch text;
    v_snippet_id uuid;
    v_snippet_created_at timestamptz;
    v_saved_attachments jsonb := '[]'::jsonb;
begin
    --------------------------------------------------------------------
    -- 1. Authentication check
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. Membership check
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

    -- FETCH USER METADATA IMMEDIATELY AFTER AUTH CHECK
    select 
        u.raw_user_meta_data ->> 'avatar_url',
        u.raw_user_meta_data ->> 'display_name',
        u.raw_user_meta_data ->> 'username'
    into 
        v_avatar_url,
        v_display_name,
        v_username
    from auth.users u
    where u.id = v_user_id;

    --------------------------------------------------------------------
    -- 3. Determine thread logic
    --------------------------------------------------------------------
    if p_parent_id is null then
        -- Root message
        v_thread_id := gen_random_uuid();
    else
        -- Find if parent is valid and ensure "no reply to reply"
        select (parent_id is null), thread_id into v_parent_is_root, v_thread_id
        from messages
        where id = p_parent_id;

        if not found then
            return jsonb_build_object(
                'status', 'error',
                'code', 'PARENT_NOT_FOUND',
                'message', 'Parent message does not exist.'
            );
        end if;

        if not v_parent_is_root then
            return jsonb_build_object(
                'status', 'error',
                'code', 'NESTED_THREAD_NOT_ALLOWED',
                'message', 'Cannot reply to a reply. Only one thread level is allowed.'
            );
        end if;
    end if;

    --------------------------------------------------------------------
    -- 4. Fetch & Decrypt Team Data Key
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
    -- NOTE: using _bytea because the output v_data_key must be binary bytes
    v_data_key := extensions.pgp_sym_decrypt_bytea(
        v_enc_dk, 
        v_master_key
    );
    
    -- Stores data key 64 bit for reuse
    v_data_key_b64 := encode(v_data_key, 'base64');

    --------------------------------------------------------------------
    -- 5. Encrypt the message content
    --------------------------------------------------------------------
    -- NOTE: We use pgp_sym_encrypt (text input) because p_content is text.
    -- BUT, the key (v_data_key) is raw bytes, so we cast it to text or use it directly?
    -- Actually, standard pgcrypto expects the KEY to be text (a passphrase).
    -- Since v_data_key is raw bytes (high entropy), we must encode it to text 
    -- so pgcrypto can use it as a "passphrase".
    
    if p_content is not null and length(p_content) > 0 then
        v_cipher := extensions.pgp_sym_encrypt(p_content, v_data_key_b64);
        v_hash:= encode(extensions.digest(p_content, 'sha256'), 'base64');
    else
        v_cipher := null;
        v_hash:= null;
    end if;

    --------------------------------------------------------------------
    -- 6. Insert message
    --------------------------------------------------------------------
    insert into messages (
        team_id,
        user_id,
        parent_id,
        thread_id,
        content_ciphertext,
        content_hash
    ) values (
        p_team_id,
        v_user_id,
        p_parent_id,
        v_thread_id,
        v_cipher,
        v_hash
    )
    returning id, created_at into v_message_id, v_created_at;


    --------------------------------------------------------------------
    -- 6.5 Process Attachments
    --------------------------------------------------------------------
    for v_att in select * from jsonb_to_recordset(p_attachments) as x(
        type text, remote_url text, ref text, commit_sha text, 
        file_path text, start_line int, end_line int, content text, patch text
    )
LOOP
    IF v_att.type = 'code' THEN

        INSERT INTO public.code_snippets (
            team_id, 
            user_id, 
            message_id,
            remote_url, 
            ref, 
            commit_sha, 
            file_path, 
            start_line, 
            end_line,
            snippet_ciphertext, 
            snippet_hash, 
            patch
        ) 
        VALUES (
            p_team_id, 
            v_user_id, 
            v_message_id,
            v_att.remote_url, 
            v_att.ref, 
            v_att.commit_sha, 
            v_att.file_path, 
            v_att.start_line, 
            v_att.end_line,
            -- Reuse the v_data_key_b64 we created earlier
            extensions.pgp_sym_encrypt(v_att.content, v_data_key_b64),
            encode(extensions.digest(v_att.content, 'sha256'), 'base64'),
            CASE
                WHEN v_att.patch IS NOT NULL THEN extensions.pgp_sym_encrypt(v_att.patch, v_data_key_b64)
                ELSE NULL
            END
        )
        RETURNING id, created_at INTO v_snippet_id, v_snippet_created_at;

        v_saved_attachments := v_saved_attachments || jsonb_build_object(
            'id', v_snippet_id,
            'type', 'code',
            'remote_url', v_att.remote_url,
            'ref', v_att.ref,
            'commit_sha', v_att.commit_sha,
            'patch', v_att.patch,
            'file_path', v_att.file_path,
            'start_line', v_att.start_line,
            'end_line', v_att.end_line,
            'content', v_att.content,
            'created_at', v_snippet_created_at
        );
    END IF;
END LOOP;

    --------------------------------------------------------------------
    -- 7. Return success JSON
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
        'attachments', v_saved_attachments,
        'u', jsonb_build_object(
                'user_id', v_user_id,
                'username', v_username,
                'display_name', v_display_name,
                'avatar_url', v_avatar_url
            )
        )
      );
end;$function$
;

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
            'patch', convert_from(
                extensions.pgp_sym_decrypt_bytea(
                    s.patch, 
                    encode(v_data_key, 'base64')
                ), 
                'utf8'
            ),
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
end;$function$
;

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
end;$function$
;


