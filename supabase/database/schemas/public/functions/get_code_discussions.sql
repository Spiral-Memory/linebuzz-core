CREATE FUNCTION public.get_code_discussions (
  p_team_id    uuid,
  p_remote_url text,
  p_file_path  text
)
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

GRANT ALL ON FUNCTION public.get_code_discussions(uuid, text, text) TO anon;

GRANT ALL ON FUNCTION public.get_code_discussions(uuid, text, text) TO authenticated;

GRANT ALL ON FUNCTION public.get_code_discussions(uuid, text, text) TO service_role;