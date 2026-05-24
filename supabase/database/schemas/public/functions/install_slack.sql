CREATE FUNCTION public.install_slack (
  p_state        uuid,
  p_access_token text,
  p_channels     jsonb
)
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

GRANT ALL ON FUNCTION public.install_slack(uuid, text, jsonb) TO anon;

GRANT ALL ON FUNCTION public.install_slack(uuid, text, jsonb) TO authenticated;

GRANT ALL ON FUNCTION public.install_slack(uuid, text, jsonb) TO service_role;