CREATE FUNCTION public.set_slack_channel (
  p_team_id    uuid,
  p_channel_id text
)
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

GRANT ALL ON FUNCTION public.set_slack_channel(uuid, text) TO anon;

GRANT ALL ON FUNCTION public.set_slack_channel(uuid, text) TO authenticated;

GRANT ALL ON FUNCTION public.set_slack_channel(uuid, text) TO service_role;