CREATE FUNCTION public.get_slack_token (
  p_team_id uuid
)
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

GRANT ALL ON FUNCTION public.get_slack_token(uuid) TO anon;

GRANT ALL ON FUNCTION public.get_slack_token(uuid) TO authenticated;

GRANT ALL ON FUNCTION public.get_slack_token(uuid) TO service_role;