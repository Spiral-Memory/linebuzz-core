CREATE FUNCTION public.create_team_and_invite (
  team_name text
)
  RETURNS jsonb
  LANGUAGE plpgsql
  SECURITY DEFINER
  AS $function$declare
    new_team_id uuid;
    invite_code text;
    is_code_unique boolean := false;
    current_user_id uuid := auth.uid();
    v_master_key text;
    v_data_key bytea;
    v_encrypted_data_key bytea;
begin
    -- 1. Check Authentication (Error: UNAUTH)
    if current_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication is required to create a team.'
        );
    end if;

    -- 2. Retrieve Master Key from Vault
    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest'; -- Ensure this matches the name you used in vault.

    -- Safety check: Ensure key exists
    if v_master_key is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'SERVER_CONFIG_ERROR',
            'message', 'Encryption configuration missing.'
        );
    end if;
    
    -- 3. Create the new team
    insert into public.teams (name, created_by)
    values (team_name, current_user_id)
    returning id into new_team_id;

    -- 4. Add the creator as the 'admin' team member
    insert into public.team_members (team_id, user_id, role)
    values (new_team_id, current_user_id, 'admin');

    -- 5. Create per team data key
    v_data_key := gen_random_bytes(32);

    -- Encrypt with latest master key
    v_encrypted_data_key := extensions.pgp_sym_encrypt_bytea(
        v_data_key,
        v_master_key -- Using the variable instead of current_setting
    );

    -- Insert into team_data_keys
    insert into public.team_data_keys (
        team_id,
        encrypted_data_key
    ) values (
        new_team_id,
        v_encrypted_data_key
    );

    -- 5. Generate a unique 5 word invite code
    while not is_code_unique loop
        SELECT string_agg(word, '-') INTO invite_code
        FROM (
            SELECT word FROM internal.bip39_words 
            ORDER BY random() 
            LIMIT 5
        ) AS secure_words;

        begin
            insert into public.invites (team_id, code, created_by)
            values (
                new_team_id, 
                extensions.crypt(invite_code, extensions.gen_salt('bf')), 
                current_user_id
            );

            is_code_unique := true;
        exception
            when unique_violation then
                null; 
        end;
    end loop;

    -- 6. Return success
    return jsonb_build_object(
        'status', 'success',
        'code', 'TEAM_CREATED',
        'team_id', new_team_id,
        'team_name', team_name,
        'role', 'admin',
        'invite_code', invite_code,
        'message', 'Team created successfully and invite code generated.'
    );
    
end;$function$;

GRANT ALL ON FUNCTION public.create_team_and_invite(text) TO anon;

GRANT ALL ON FUNCTION public.create_team_and_invite(text) TO authenticated;

GRANT ALL ON FUNCTION public.create_team_and_invite(text) TO service_role;