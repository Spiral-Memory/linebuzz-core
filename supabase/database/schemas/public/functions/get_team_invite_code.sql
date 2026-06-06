CREATE OR REPLACE FUNCTION public.get_team_invite_code(p_team_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal', 'extensions', 'vault', 'pg_catalog'
AS $function$declare
    v_user_id uuid := auth.uid();
    v_role text;
    v_encrypted_code bytea;
    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;
    v_decrypted_code text;
begin
    -- 1. Auth check
    if v_user_id is null then
        return jsonb_build_object('status', 'error', 'code', 'UNAUTH', 'message', 'Authentication required.');
    end if;

    -- 2. Verify caller is an admin of the team
    select role into v_role
    from public.team_members
    where team_id = p_team_id and user_id = v_user_id;

    if v_role != 'admin' or v_role is null then
        return jsonb_build_object('status', 'error', 'code', 'FORBIDDEN', 'message', 'Only team admins can retrieve the invite code.');
    end if;

    -- 3. Fetch encrypted invite code
    select encrypted_code into v_encrypted_code
    from public.invites
    where team_id = p_team_id;

    if v_encrypted_code is null then
        return jsonb_build_object('status', 'error', 'code', 'NOT_FOUND', 'message', 'Invite code not found or was generated under old schema.');
    end if;

    -- 4. Load encryption keys
    select encrypted_data_key into v_enc_dk
    from public.team_data_keys
    where team_id = p_team_id;

    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    if v_enc_dk is null or v_master_key is null then
        return jsonb_build_object('status', 'error', 'code', 'KEY_ERROR', 'message', 'Decryption keys unavailable.');
    end if;

    -- 5. Decrypt
    v_data_key := extensions.pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);
    v_decrypted_code := convert_from(
        extensions.pgp_sym_decrypt_bytea(v_encrypted_code, encode(v_data_key, 'base64')),
        'utf8'
    );

    return jsonb_build_object(
        'status', 'success',
        'invite_code', v_decrypted_code
    );
end;$function$;

GRANT ALL ON FUNCTION public.get_team_invite_code(uuid) TO authenticated;
GRANT ALL ON FUNCTION public.get_team_invite_code(uuid) TO service_role;
