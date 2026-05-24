CREATE FUNCTION public.join_team_with_code (
  p_invite_code text
)
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

GRANT ALL ON FUNCTION public.join_team_with_code(text) TO anon;

GRANT ALL ON FUNCTION public.join_team_with_code(text) TO authenticated;

GRANT ALL ON FUNCTION public.join_team_with_code(text) TO service_role;