SET check_function_bodies = false;
ALTER TABLE public.team_integrations DROP COLUMN access_token;
ALTER FUNCTION internal.handle_slack_notify_trigger() SET search_path TO internal, vault, extensions, pg_catalog;
ALTER FUNCTION public.create_message(uuid, text, uuid, uuid, jsonb, boolean) SET search_path TO public, internal, extensions, vault, pg_catalog;
CREATE OR REPLACE FUNCTION public.create_team_and_invite(team_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal', 'extensions', 'vault', 'pg_catalog'
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
            insert into public.invites (team_id, code, created_by, encrypted_code)
            values (
                new_team_id, 
                extensions.crypt(invite_code, extensions.gen_salt('bf')), 
                current_user_id,
                extensions.pgp_sym_encrypt(invite_code, encode(v_data_key, 'base64'))
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
CREATE OR REPLACE FUNCTION public.disconnect_slack(p_team_id uuid)
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
ALTER FUNCTION public.get_code_discussions(uuid, text, text) SET search_path TO public, extensions, vault, pg_catalog;
ALTER FUNCTION public.get_message_by_id(uuid, uuid) SET search_path TO public, extensions, vault, pg_catalog;
ALTER FUNCTION public.get_slack_install_url(uuid) SET search_path TO public, internal, pg_catalog;
CREATE OR REPLACE FUNCTION public.get_slack_payload(p_message_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'internal', 'extensions', 'vault'
AS $function$declare
    -- Context Variables
    v_team_id uuid;
    v_user_id uuid;
    v_msg_ciphertext bytea;
    v_token_ciphertext bytea;

    -- Key Variables
    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;

    -- Output Variables
    v_slack_channel_id text;
    v_display_name text;
    v_username text;
    v_avatar_url text;

    -- Quoted message decryption variables
    v_quoted_id uuid;
    v_quoted_ciphertext bytea;
    v_quoted_user_id uuid;
    v_quoted_display_name text;
    v_quoted_username text;
    v_quoted_msg text;
    v_quoted_source text;
    v_quoted_metadata jsonb;

    -- Thread/parent variables
    v_parent_id uuid;
    v_parent_slack_ts text;

    -- Code snippet decryption variables
    v_code_snippets_json jsonb;
begin
    --------------------------------------------------------------------
    -- 1. Service Role Gate
    --------------------------------------------------------------------
    -- This function must ONLY be called by our trusted Edge Function.
    -- The service_role bypasses RLS, which is necessary to read tokens.
    if auth.role() <> 'service_role' then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'Access denied.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. Resolve Context and Ciphertexts
    --------------------------------------------------------------------
    select 
        m.team_id, 
        m.user_id, 
        m.content_ciphertext, 
        m.quoted_id,
        m.parent_id,
        tok.access_token, 
        ti.settings->>'active_channel_id'
    into 
        v_team_id, 
        v_user_id, 
        v_msg_ciphertext, 
        v_quoted_id,
        v_parent_id,
        v_token_ciphertext, 
        v_slack_channel_id
    from public.messages m
    join public.team_integrations ti on m.team_id = ti.team_id
    left join public.team_integration_tokens tok on tok.team_id = ti.team_id and tok.provider = ti.provider
    where m.id = p_message_id and ti.provider = 'slack';

    if not found then
        return jsonb_build_object(
            'status', 'error', 
            'code', 'NOT_FOUND',
            'message', 'Message or Slack integration not found.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2b. Resolve Parent Thread Timestamp (for Slack threading)
    --------------------------------------------------------------------
    if v_parent_id is not null then
        select coalesce(source_metadata->>'slack_thread_ts', source_metadata->>'slack_event_ts')
        into v_parent_slack_ts
        from public.messages
        where id = v_parent_id;
    end if;

    --------------------------------------------------------------------
    -- 3. Resolve Keys
    --------------------------------------------------------------------
    -- Get the team-specific data key
    select encrypted_data_key into v_enc_dk 
    from public.team_data_keys 
    where team_id = v_team_id;

    -- Get the global master key from Vault
    select decrypted_secret into v_master_key 
    from vault.decrypted_secrets 
    where name = 'app_master_key_latest';

    if v_enc_dk is null or v_master_key is null then
        return jsonb_build_object(
            'status', 'error', 
            'code', 'KEY_ERROR',
            'message', 'Decryption keys unavailable.'
        );
    end if;

    -- Phase 1: Decrypt the Data Key using Master Key
    v_data_key := extensions.pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);

    --------------------------------------------------------------------
    -- 4. User Metadata Lookups
    --------------------------------------------------------------------
    select 
        raw_user_meta_data ->> 'display_name',
        raw_user_meta_data ->> 'username',
        raw_user_meta_data ->> 'avatar_url'
    into 
        v_display_name, 
        v_username,
        v_avatar_url
    from auth.users where id = v_user_id;

    --------------------------------------------------------------------
    -- 4b. Quoted Message Lookup and Decryption
    --------------------------------------------------------------------
    if v_quoted_id is not null then
        select 
            content_ciphertext,
            user_id,
            source,
            source_metadata
        into 
            v_quoted_ciphertext,
            v_quoted_user_id,
            v_quoted_source,
            v_quoted_metadata
        from public.messages
        where id = v_quoted_id;

        if v_quoted_ciphertext is not null then
            v_quoted_msg := convert_from(
                extensions.pgp_sym_decrypt_bytea(v_quoted_ciphertext, encode(v_data_key, 'base64')), 
                'utf8'
            );

            if v_quoted_source = 'slack' and v_quoted_metadata ? 'username' then
                v_quoted_username := v_quoted_metadata ->> 'username';
            else
                select 
                    raw_user_meta_data ->> 'display_name',
                    raw_user_meta_data ->> 'username'
                into 
                    v_quoted_display_name, 
                    v_quoted_username
                from auth.users where id = v_quoted_user_id;
            end if;
        end if;
    end if;

    --------------------------------------------------------------------
    -- 4c. Code Snippets Lookup and Decryption
    --------------------------------------------------------------------
    select 
        coalesce(
            jsonb_agg(
                jsonb_build_object(
                    'file_path', s.file_path,
                    'start_line', s.start_line,
                    'end_line', s.end_line,
                    'remote_url', s.remote_url,
                    'content', convert_from(
                        extensions.pgp_sym_decrypt_bytea(s.snippet_ciphertext, encode(v_data_key, 'base64')), 
                        'utf8'
                    )
                )
            ),
            '[]'::jsonb
        )
    into 
        v_code_snippets_json
    from public.code_snippets s
    where s.message_id = p_message_id;

    --------------------------------------------------------------------
    -- 5. Final Decryption and Assembly
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'payload', jsonb_build_object(
            'channel_id', v_slack_channel_id,
            'user_name', coalesce(v_username, v_display_name, 'Buzz Member'),
            'user_avatar_url', v_avatar_url,
            'quoted_message', case 
                when v_quoted_msg is not null then jsonb_build_object(
                    'user_name', coalesce(v_quoted_username, v_quoted_display_name, 'Buzz Member'),
                    'content', v_quoted_msg
                )
                else null
            end,
            'code_snippets', v_code_snippets_json,
            'parent_slack_ts', v_parent_slack_ts,
            -- Phase 2: Decrypt the Token and Message using the Data Key
            'decrypted_token', convert_from(
                extensions.pgp_sym_decrypt_bytea(v_token_ciphertext, encode(v_data_key, 'base64')), 
                'utf8'
            ),
            'decrypted_message', convert_from(
                extensions.pgp_sym_decrypt_bytea(v_msg_ciphertext, encode(v_data_key, 'base64')), 
                'utf8'
            )
        )
    );
end;$function$;
CREATE OR REPLACE FUNCTION public.get_slack_token(p_team_id uuid)
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
    from public.team_integration_tokens
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
CREATE FUNCTION public.get_team_invite_code(p_team_id uuid)
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
CREATE OR REPLACE FUNCTION public.install_slack(p_state uuid, p_access_token text, p_channels jsonb)
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
        settings
    )
    values (
        v_team_id,
        'slack',
        jsonb_build_object(
            'channels', p_channels,
            'active_channel_id', null
        )
    )
    on conflict (team_id, provider) 
    do update set 
        settings = excluded.settings,
        updated_at = now();

    insert into public.team_integration_tokens (
        team_id,
        provider,
        access_token
    ) values (
        v_team_id,
        'slack',
        v_encrypted_token
    )
    on conflict (team_id, provider)
    do update set
        access_token = excluded.access_token,
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
ALTER FUNCTION public.join_team_with_code(text) SET search_path TO public, extensions, pg_catalog;
ALTER TABLE public.invites ADD COLUMN encrypted_code bytea;
CREATE TABLE public.team_integration_tokens (team_id uuid NOT NULL, provider text NOT NULL, access_token bytea NOT NULL, created_at timestamp with time zone DEFAULT now() NOT NULL, updated_at timestamp with time zone DEFAULT now() NOT NULL);
ALTER TABLE public.team_integration_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_integration_tokens ADD CONSTRAINT team_integration_tokens_pkey PRIMARY KEY (team_id, provider);
ALTER TABLE public.team_integration_tokens ADD CONSTRAINT team_integration_tokens_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;
