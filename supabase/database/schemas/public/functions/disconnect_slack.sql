CREATE FUNCTION public.disconnect_slack (
  p_team_id uuid
)
  RETURNS jsonb
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'internal', 'pg_catalog'
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

    delete from public.team_integration_tokens
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

GRANT ALL ON FUNCTION public.disconnect_slack(uuid) TO anon;

GRANT ALL ON FUNCTION public.disconnect_slack(uuid) TO authenticated;

GRANT ALL ON FUNCTION public.disconnect_slack(uuid) TO service_role;