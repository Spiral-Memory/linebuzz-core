CREATE FUNCTION public.get_message_by_id (
  p_team_id    uuid,
  p_message_id uuid
)
  RETURNS jsonb
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
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

GRANT ALL ON FUNCTION public.get_message_by_id(uuid, uuid) TO anon;

GRANT ALL ON FUNCTION public.get_message_by_id(uuid, uuid) TO authenticated;

GRANT ALL ON FUNCTION public.get_message_by_id(uuid, uuid) TO service_role;