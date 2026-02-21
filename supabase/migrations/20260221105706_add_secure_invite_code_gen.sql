create schema if not exists "internal";


  create table "internal"."bip39_words" (
    "id" integer not null,
    "word" text not null
      );


alter table "internal"."bip39_words" enable row level security;

CREATE UNIQUE INDEX bip39_words_pkey ON internal.bip39_words USING btree (id);

CREATE INDEX idx_bip39_words_id ON internal.bip39_words USING btree (id);

alter table "internal"."bip39_words" add constraint "bip39_words_pkey" PRIMARY KEY using index "bip39_words_pkey";

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.create_team_and_invite(team_name text)
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
        'invite_code', invite_code,
        'message', 'Team created successfully and invite code generated.'
    );
    
end;$function$
;

CREATE OR REPLACE FUNCTION public.get_code_discussions(p_team_id uuid, p_remote_url text, p_file_path text)
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
end;$function$
;

CREATE OR REPLACE FUNCTION public.get_messages(p_team_id uuid, p_limit integer, p_anchor_id uuid DEFAULT NULL::uuid, p_direction text DEFAULT 'before'::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions', 'vault'
AS $function$declare
    v_user_id uuid := auth.uid();

    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;

    v_rows jsonb := '[]'::jsonb;
    v_total_count int := 0; 
    v_anchor_ts timestamptz;
begin
    --------------------------------------------------------------------
    -- 1. auth check
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. membership check
    --------------------------------------------------------------------
    if not exists (
        select 1 from team_members
        where team_id = p_team_id
        and user_id = v_user_id
    ) then
        return jsonb_build_object(
            'status', 'error',
            'code', 'FORBIDDEN',
            'message', 'User is not a member of this team.'
        );
    end if;

    --------------------------------------------------------------------
    -- 3. Resolve Anchor Coordinates
    --------------------------------------------------------------------
    if p_anchor_id is not null then
        select created_at into v_anchor_ts 
        from messages 
        where id = p_anchor_id and team_id = p_team_id;
    end if;

    --------------------------------------------------------------------
    -- 4. load team's encrypted data key
    --------------------------------------------------------------------
    select encrypted_data_key
    into v_enc_dk
    from team_data_keys
    where team_id = p_team_id;

    if v_enc_dk is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'MISSING_TEAM_KEY',
            'message', 'Team encryption key missing.'
        );
    end if;

    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    -- decrypt team data key
    v_data_key := pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);

    --------------------------------------------------------------------
    -- 4. Get Total Count
    --------------------------------------------------------------------
    select count(*)
    into v_total_count
    from messages
    where team_id = p_team_id;

--------------------------------------------------------------------
    -- 5. Fetch + Decrypt Messages (Unified Directional Query)
--------------------------------------------------------------------
    select jsonb_agg(sub_final.msg_obj order by sub_final.created_at ASC)
    into v_rows
    from (
        select 
            m_filtered.created_at,
            jsonb_build_object(
                'message_id', m_filtered.id,
                'quoted_id', m_filtered.quoted_id,
                'quoted_message', (
                    select jsonb_build_object(
                        'content', convert_from(
                            extensions.pgp_sym_decrypt_bytea(
                                qm.content_ciphertext,
                                encode(v_data_key, 'base64')
                            ),
                            'utf8'
                        ),
                        'u', jsonb_build_object(
                            'user_id', qu.id,
                            'avatar_url', qu.raw_user_meta_data ->> 'avatar_url',
                            'display_name', qu.raw_user_meta_data ->> 'display_name',
                            'username', qu.raw_user_meta_data ->> 'username'
                        )
                    )
                    from messages qm
                    join auth.users qu on qu.id = qm.user_id
                    where qm.id = m_filtered.quoted_id
                ),
                'parent_id', m_filtered.parent_id,
                'thread_id', m_filtered.thread_id,
                'content', case 
                    when m_filtered.content_ciphertext is not null 
                    then convert_from(extensions.pgp_sym_decrypt_bytea(m_filtered.content_ciphertext, encode(v_data_key, 'base64')), 'utf8')
                    else null 
                end,
                'attachments', (
                    select coalesce(jsonb_agg(
                        jsonb_build_object(
                            'id', s.id, 
                            'type', 'code',
                            'remote_url', s.remote_url,
                            'ref', s.ref,
                            'commit_sha', s.commit_sha,
                            'file_path', s.file_path,
                            'start_line', s.start_line,
                            'end_line', s.end_line,
                            'content', convert_from(extensions.pgp_sym_decrypt_bytea(s.snippet_ciphertext, encode(v_data_key, 'base64')), 'utf8'),
                            'patch', convert_from(extensions.pgp_sym_decrypt_bytea(s.patch, encode(v_data_key, 'base64')), 'utf8')
                        ) ORDER BY s.created_at ASC
                    ), '[]'::jsonb)
                    from public.code_snippets s where s.message_id = m_filtered.id
                ),
                'created_at', m_filtered.created_at,
                'u', jsonb_build_object(
                    'user_id', m_filtered.user_id,
                    'avatar_url', u.raw_user_meta_data ->> 'avatar_url',
                    'display_name', u.raw_user_meta_data ->> 'display_name',
                    'username', u.raw_user_meta_data ->> 'username'
                )
            ) as msg_obj
        from (
            -- Sub-query handles the high-performance directional seek
            select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id
            from (
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id
                    from messages
                    where team_id = p_team_id
                      and p_direction IN ('before', 'around')
                      and (v_anchor_ts is null or (created_at, id) < (v_anchor_ts, p_anchor_id))
                    order by created_at DESC, id DESC
                    limit p_limit
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id
                    from messages
                    where id = p_anchor_id and p_direction = 'around'
                )
                UNION ALL
                (
                    select id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id
                    from messages
                    where team_id = p_team_id
                      and p_direction IN ('after', 'around')
                      and v_anchor_ts is not null 
                      and (created_at, id) > (v_anchor_ts, p_anchor_id)
                    order by created_at ASC, id ASC
                    limit p_limit
                )
            ) m_union
            group by id, created_at, user_id, content_ciphertext, parent_id, thread_id, quoted_id
        ) m_filtered
        join auth.users u on u.id = m_filtered.user_id
    ) sub_final;

    --------------------------------------------------------------------
    -- 6. Wrap inside success JSONB
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGES_LOADED',
        'meta', jsonb_build_object(
            'total', v_total_count,
            'limit', p_limit,
            'anchor', p_anchor_id,
            'direction', p_direction,
            'oldest_id', (v_rows->0)->>'message_id',
            'newest_id', (v_rows->-1)->>'message_id'
        ),
        'messages', coalesce(v_rows, '[]'::jsonb)
    );
end;$function$
;

CREATE OR REPLACE FUNCTION public.join_team_with_code(p_invite_code text)
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
end;$function$
;


