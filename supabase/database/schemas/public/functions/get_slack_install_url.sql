CREATE FUNCTION public.get_slack_install_url (
  p_team_id uuid
)
  RETURNS jsonb
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'internal', 'pg_catalog'
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

GRANT ALL ON FUNCTION public.get_slack_install_url(uuid) TO anon;

GRANT ALL ON FUNCTION public.get_slack_install_url(uuid) TO authenticated;

GRANT ALL ON FUNCTION public.get_slack_install_url(uuid) TO service_role;