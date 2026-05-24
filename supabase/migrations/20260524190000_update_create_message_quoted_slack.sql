-- Recreate create_message to return quoted message source and source_metadata
CREATE OR REPLACE FUNCTION public.create_message(
    p_team_id uuid, 
    p_content text, 
    p_parent_id uuid DEFAULT NULL::uuid, 
    p_quoted_id uuid DEFAULT NULL::uuid, 
    p_attachments jsonb DEFAULT '[]'::jsonb,
    p_sync_to_slack boolean DEFAULT false
)
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
