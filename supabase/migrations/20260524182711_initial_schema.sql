SET check_function_bodies = false;
CREATE SCHEMA internal AUTHORIZATION postgres;
CREATE TABLE internal.app_settings (key text NOT NULL, value text NOT NULL);
ALTER TABLE internal.app_settings ADD CONSTRAINT app_settings_pkey PRIMARY KEY (key);
CREATE TABLE internal.bip39_words (id integer NOT NULL, word text NOT NULL);
ALTER TABLE internal.bip39_words ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal.bip39_words ADD CONSTRAINT bip39_words_pkey PRIMARY KEY (id);
CREATE INDEX idx_bip39_words_id ON internal.bip39_words (id);
CREATE EXTENSION pg_cron WITH SCHEMA pg_catalog;
CREATE FUNCTION public.create_message(p_team_id uuid, p_content text, p_parent_id uuid DEFAULT NULL::uuid, p_quoted_id uuid DEFAULT NULL::uuid, p_attachments jsonb DEFAULT '[]'::jsonb, p_sync_to_slack boolean DEFAULT false)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
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
    v_data_key := extensions.pgp_sym_decrypt_bytea(
        v_enc_dk, 
        v_master_key
    );
    
    -- Stores data key 64 bit for reuse
    v_data_key_b64 := encode(v_data_key, 'base64');

    --------------------------------------------------------------------
    -- 5. Encrypt the message content
    --------------------------------------------------------------------
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
        quoted_id,
        parent_id,
        thread_id,
        content_ciphertext,
        content_hash,
        sync_to_slack
    ) values (
        p_team_id,
        v_user_id,
        p_quoted_id,
        p_parent_id,
        v_thread_id,
        v_cipher,
        v_hash,
        p_sync_to_slack
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
    -- 7. Return success JSON with quoted message source details
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGE_CREATED',
        'message', jsonb_build_object(
            'message_id', v_message_id,
            'thread_id', v_thread_id,
            'quoted_id', p_quoted_id,
            'quoted_message', (
                select jsonb_build_object(
                    'content', convert_from(
                        pgp_sym_decrypt_bytea(
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
                where qm.id = p_quoted_id
            ),
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
end;$function$;
CREATE FUNCTION public.create_team_and_invite(team_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$declare
    new_team_id uuid;
    invite_code text;
    is_code_unique boolean := false;
    current_user_id uuid := auth.uid();
    v_master_key text;
    v_data_key bytea;
    v_encrypted_data_key bytea;
begin
    -- 1. Check Authentication (Error: UNAUTH)
    if current_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication is required to create a team.'
        );
    end if;

    -- 2. Retrieve Master Key from Vault
    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest'; -- Ensure this matches the name you used in vault.

    -- Safety check: Ensure key exists
    if v_master_key is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'SERVER_CONFIG_ERROR',
            'message', 'Encryption configuration missing.'
        );
    end if;
    
    -- 3. Create the new team
    insert into public.teams (name, created_by)
    values (team_name, current_user_id)
    returning id into new_team_id;

    -- 4. Add the creator as the 'admin' team member
    insert into public.team_members (team_id, user_id, role)
    values (new_team_id, current_user_id, 'admin');

    -- 5. Create per team data key
    v_data_key := gen_random_bytes(32);

    -- Encrypt with latest master key
    v_encrypted_data_key := extensions.pgp_sym_encrypt_bytea(
        v_data_key,
        v_master_key -- Using the variable instead of current_setting
    );

    -- Insert into team_data_keys
    insert into public.team_data_keys (
        team_id,
        encrypted_data_key
    ) values (
        new_team_id,
        v_encrypted_data_key
    );

    -- 5. Generate a unique 5 word invite code
    while not is_code_unique loop
        SELECT string_agg(word, '-') INTO invite_code
        FROM (
            SELECT word FROM internal.bip39_words 
            ORDER BY random() 
            LIMIT 5
        ) AS secure_words;

        begin
            insert into public.invites (team_id, code, created_by)
            values (
                new_team_id, 
                extensions.crypt(invite_code, extensions.gen_salt('bf')), 
                current_user_id
            );

            is_code_unique := true;
        exception
            when unique_violation then
                null; 
        end;
    end loop;

    -- 6. Return success
    return jsonb_build_object(
        'status', 'success',
        'code', 'TEAM_CREATED',
        'team_id', new_team_id,
        'team_name', team_name,
        'role', 'admin',
        'invite_code', invite_code,
        'message', 'Team created successfully and invite code generated.'
    );
    
end;$function$;
CREATE FUNCTION public.disconnect_slack(p_team_id uuid)
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
CREATE FUNCTION public.get_code_discussions(p_team_id uuid, p_remote_url text, p_file_path text)
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
end;$function$;
CREATE FUNCTION public.get_message_by_id(p_team_id uuid, p_message_id uuid)
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
CREATE FUNCTION public.get_messages(p_team_id uuid, p_limit integer, p_anchor_id uuid DEFAULT NULL::uuid, p_direction text DEFAULT 'before'::text)
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
CREATE FUNCTION public.get_slack_install_url(p_team_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
declare
    v_state_id uuid;
    v_base_url text;
    v_user_id uuid := auth.uid();
    v_role text;
    v_settings jsonb;
begin
    --------------------------------------------------------------------
    -- 1. Check Authentication
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object('status', 'error', 'code', 'UNAUTH', 'message', 'Authentication required.');
    end if;

    --------------------------------------------------------------------
    -- 2. Verify Admin Permissions
    --------------------------------------------------------------------
    select role into v_role from public.team_members 
    where team_id = p_team_id and user_id = v_user_id;

    if v_role != 'admin' or v_role is null then
        return jsonb_build_object('status', 'error', 'code', 'FORBIDDEN', 'message', 'Admin access required.');
    end if;

    --------------------------------------------------------------------
    -- 3. Check if Already Connected
    --------------------------------------------------------------------
    select settings into v_settings from public.team_integrations
    where team_id = p_team_id and provider = 'slack';

    if found then
        return jsonb_build_object(
            'status', 'success', 
            'code', 'ALREADY_CONNECTED', 
            'settings', v_settings, 
            'message', 'Slack is already connected.'
        );
    end if;

    --------------------------------------------------------------------
    -- 4. Fetch Slack Configuration
    --------------------------------------------------------------------
    select value into v_base_url from internal.app_settings where key = 'slack_base_url';

    if v_base_url is null then
        return jsonb_build_object('status', 'error', 'code', 'CONFIG_ERROR', 'message', 'Configuration not found.');
    end if;

    --------------------------------------------------------------------
    -- 5. Generate State
    --------------------------------------------------------------------
    insert into public.integration_oauth_states (provider, user_id, team_id)
    values ('slack', v_user_id, p_team_id)
    returning id into v_state_id;

    return jsonb_build_object(
        'status', 'success', 
        'code', 'URL_GENERATED', 
        'url', v_base_url || '&state=' || v_state_id
    );
end;
$function$;
CREATE FUNCTION public.get_slack_payload(p_message_id uuid)
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
        ti.access_token, 
        ti.settings->>'active_channel_id'
    into 
        v_team_id, 
        v_user_id, 
        v_msg_ciphertext, 
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
        raw_user_meta_data ->> 'username'
    into 
        v_display_name, 
        v_username
    from auth.users where id = v_user_id;

    --------------------------------------------------------------------
    -- 5. Final Decryption and Assembly
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'payload', jsonb_build_object(
            'channel_id', v_slack_channel_id,
            'user_name', coalesce(v_username, v_display_name, 'Buzz Member'),
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
CREATE FUNCTION public.get_slack_token(p_team_id uuid)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal', 'extensions', 'vault'
AS $function$declare
    v_token_ciphertext bytea;
    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;
begin
    --------------------------------------------------------------------
    -- 1. Authentication check (Only callable by service_role)
    --------------------------------------------------------------------
    if auth.role() <> 'service_role' then
        raise exception 'Access denied.';
    end if;

    --------------------------------------------------------------------
    -- 2. Fetch the ciphertext of the token
    --------------------------------------------------------------------
    select access_token into v_token_ciphertext
    from public.team_integrations
    where team_id = p_team_id and provider = 'slack';

    if v_token_ciphertext is null then
        return null;
    end if;

    --------------------------------------------------------------------
    -- 3. Decrypt team data key using master key from vault
    --------------------------------------------------------------------
    select encrypted_data_key into v_enc_dk
    from public.team_data_keys
    where team_id = p_team_id;

    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    if v_enc_dk is null or v_master_key is null then
        raise exception 'Decryption keys unavailable.';
    end if;

    v_data_key := extensions.pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);

    --------------------------------------------------------------------
    -- 4. Decrypt and return the Slack token as text
    --------------------------------------------------------------------
    return convert_from(
        extensions.pgp_sym_decrypt_bytea(v_token_ciphertext, encode(v_data_key, 'base64')), 
        'utf8'
    );
end;$function$;
CREATE FUNCTION public.insert_slack_message(p_team_id uuid, p_content text, p_source_metadata jsonb)
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
CREATE FUNCTION public.install_slack(p_state uuid, p_access_token text, p_channels jsonb)
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
CREATE FUNCTION public.join_team_with_code(p_invite_code text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$declare
    team_to_join_id uuid;
    current_user_id uuid := auth.uid();
    existing_member_role text;
    team_name text;
begin
    -- 1. Check Authentication (Error: UNAUTH)
    if current_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication is required to join a team.'
        );
    end if;

    -- 2. Find the team associated with the invite code
    select i.team_id, t.name
    into team_to_join_id, team_name
    from public.invites i
    join public.teams t ON i.team_id = t.id
    where i.code = extensions.crypt(lower(trim(p_invite_code)), i.code);

    -- 3. Check for invalid code (Error: INVALID_CODE)
    if team_to_join_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'INVALID_CODE',
            'message', 'Invalid invite code or the invite has expired.'
        );
    end if;

    -- 4. Check if the user is already a member
    select role
    into existing_member_role
    from public.team_members
    where team_id = team_to_join_id and user_id = current_user_id;

    -- 5. Handle already a member (Warning: ALREADY_MEMBER)
    if existing_member_role is not null then
        return jsonb_build_object(
            'status', 'warning',
            'code', 'ALREADY_MEMBER',
            'team_id', team_to_join_id,
            'team_name', team_name,
            'role', existing_member_role,
            'message', 'You are already a member of this team.'
        );
    end if;

    -- 6. Add the user to the team
    insert into public.team_members (team_id, user_id, role)
    values (team_to_join_id, current_user_id, 'member');

    -- 7. Return success
    return jsonb_build_object(
        'status', 'success',
        'code', 'JOINED',
        'team_id', team_to_join_id,
        'team_name', team_name,
        'message', 'Successfully joined team.'
    );
end;$function$;
CREATE FUNCTION public.set_slack_channel(p_team_id uuid, p_channel_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$declare
    v_user_id uuid := auth.uid();
    v_role text;
begin
    --------------------------------------------------------------------
    -- 1. Check Authentication (Error: UNAUTH)
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. Verify Admin Permissions (Error: FORBIDDEN)
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
    -- 3. Update Active Channel
    --------------------------------------------------------------------
    -- Uses jsonb_set to surgically update the active_channel_id 
    -- while preserving the rest of the settings object (like the channel list).
    update public.team_integrations
    set settings = jsonb_set(settings, '{active_channel_id}', to_jsonb(p_channel_id)),
        updated_at = now()
    where team_id = p_team_id and provider = 'slack';

    --------------------------------------------------------------------
    -- 4. Return Success
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'CHANNEL_UPDATED',
        'message', 'Active channel updated successfully.'
    );
end;$function$;
CREATE TABLE public.code_snippets (id uuid DEFAULT gen_random_uuid() NOT NULL, team_id uuid NOT NULL, user_id uuid NOT NULL, message_id uuid NOT NULL, remote_url text NOT NULL, ref text, commit_sha text, file_path text NOT NULL, start_line integer NOT NULL, end_line integer NOT NULL, snippet_ciphertext bytea NOT NULL, created_at timestamp with time zone DEFAULT now(), snippet_hash text, patch bytea);
ALTER TABLE public.code_snippets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.code_snippets ADD CONSTRAINT code_context_pkey PRIMARY KEY (id);
ALTER TABLE public.code_snippets ADD CONSTRAINT code_context_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);
CREATE INDEX idx_snippets_team_url_path ON public.code_snippets (team_id, remote_url, file_path);
CREATE INDEX idx_snippets_team_message ON public.code_snippets (team_id, message_id);
CREATE TABLE public.integration_oauth_states (id uuid DEFAULT gen_random_uuid() NOT NULL, provider text NOT NULL, user_id uuid, team_id uuid NOT NULL, expires_at timestamp with time zone DEFAULT (now() + '00:15:00'::interval), created_at timestamp with time zone DEFAULT now());
ALTER TABLE public.integration_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.integration_oauth_states ADD CONSTRAINT integration_oauth_states_pkey PRIMARY KEY (id);
ALTER TABLE public.integration_oauth_states ADD CONSTRAINT integration_oauth_states_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;
CREATE TABLE public.invites (id uuid DEFAULT gen_random_uuid() NOT NULL, team_id uuid NOT NULL, code text NOT NULL, created_by uuid NOT NULL);
ALTER TABLE public.invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invites ADD CONSTRAINT invites_code_key UNIQUE (code);
ALTER TABLE public.invites ADD CONSTRAINT invites_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE public.invites ADD CONSTRAINT invites_pkey PRIMARY KEY (id);
CREATE TABLE public.messages (id uuid DEFAULT gen_random_uuid() NOT NULL, team_id uuid NOT NULL, user_id uuid NOT NULL, parent_id uuid, thread_id uuid, content_ciphertext bytea, content_hash text, created_at timestamp with time zone DEFAULT now(), quoted_id uuid, sync_to_slack boolean DEFAULT false NOT NULL, source text DEFAULT 'app'::text, source_metadata jsonb);
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ADD CONSTRAINT messages_pkey PRIMARY KEY (id);
ALTER TABLE public.code_snippets ADD CONSTRAINT code_context_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.messages(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE public.messages ADD CONSTRAINT messages_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);
CREATE INDEX idx_messages_pagination ON public.messages (team_id, created_at DESC, id DESC);
CREATE TABLE public.team_data_keys (encrypted_data_key bytea NOT NULL, updated_at timestamp with time zone DEFAULT now(), team_id uuid NOT NULL);
ALTER TABLE public.team_data_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_data_keys ADD CONSTRAINT team_data_keys_pkey PRIMARY KEY (team_id);
CREATE TABLE public.team_integrations (team_id uuid NOT NULL, provider text NOT NULL, access_token bytea NOT NULL, settings jsonb DEFAULT '{}'::jsonb, created_at timestamp with time zone DEFAULT now(), updated_at timestamp with time zone DEFAULT now());
ALTER PUBLICATION supabase_realtime ADD TABLE public.code_snippets, TABLE public.messages, TABLE public.team_integrations;
ALTER TABLE public.team_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_integrations ADD CONSTRAINT team_integrations_pkey PRIMARY KEY (team_id, provider);
CREATE TABLE public.team_members (team_id uuid NOT NULL, user_id uuid NOT NULL, role text);
CREATE POLICY "team can read code snippets" ON public.code_snippets FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.team_members tm
  WHERE ((tm.team_id = code_snippets.team_id) AND (tm.user_id = auth.uid())))));
CREATE POLICY "team members can read messages" ON public.messages FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.team_members tm
  WHERE ((tm.team_id = messages.team_id) AND (tm.user_id = auth.uid())))));
CREATE POLICY "Team members can view their own integrations" ON public.team_integrations FOR SELECT TO authenticated USING ((EXISTS ( SELECT 1
   FROM public.team_members
  WHERE ((team_members.team_id = team_integrations.team_id) AND (team_members.user_id = auth.uid())))));
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ADD CONSTRAINT team_members_pkey PRIMARY KEY (team_id, user_id);
ALTER TABLE public.team_members ADD CONSTRAINT team_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON UPDATE CASCADE ON DELETE CASCADE;
CREATE POLICY "users can read own memberships" ON public.team_members FOR SELECT USING ((user_id = auth.uid()));
CREATE TABLE public.teams (id uuid DEFAULT gen_random_uuid() NOT NULL, name text NOT NULL, created_by uuid NOT NULL, created_at timestamp with time zone DEFAULT now() NOT NULL);
ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.teams ADD CONSTRAINT teams_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE public.teams ADD CONSTRAINT teams_name_created_by_unique UNIQUE (name, created_by);
ALTER TABLE public.teams ADD CONSTRAINT teams_pkey PRIMARY KEY (id);
ALTER TABLE public.code_snippets ADD CONSTRAINT code_context_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE public.invites ADD CONSTRAINT invites_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE public.messages ADD CONSTRAINT messages_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE public.team_data_keys ADD CONSTRAINT team_data_keys_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE public.team_integrations ADD CONSTRAINT team_integrations_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;
ALTER TABLE public.team_members ADD CONSTRAINT team_members_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;
