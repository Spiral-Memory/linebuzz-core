


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";






CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE OR REPLACE FUNCTION "public"."create_message"("p_team_id" "uuid", "p_parent_id" "uuid", "p_content" "text", "p_is_code_thread" boolean DEFAULT false) RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'vault', 'extensions'
    AS $$declare
    v_user_id uuid := auth.uid();
    v_avatar_url text;
    v_display_name text;
    v_username text;

    v_thread_id uuid;
    v_message_id uuid;
    v_created_at timestamptz;
    v_enc_dk bytea;      -- Encrypted Data Key (from DB)
    v_data_key bytea;    -- Decrypted Data Key (Raw Bytes)
    v_cipher bytea;      -- Final Encrypted Message

    v_master_key text;   -- Master Key (Passphrase from Vault)
    v_parent_is_root boolean;
begin
    --------------------------------------------------------------------
    -- 1. Authentication check
    --------------------------------------------------------------------
    if v_user_id is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'UNAUTH',
            'message', 'Authentication required.'
        );
    end if;

    --------------------------------------------------------------------
    -- 2. Membership check
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

    -- FETCH USER METADATA IMMEDIATELY AFTER AUTH CHECK
    select 
        u.raw_user_meta_data ->> 'avatar_url',
        u.raw_user_meta_data ->> 'display_name',
        u.raw_user_meta_data ->> 'username'
    into 
        v_avatar_url,
        v_display_name,
        v_username
    from auth.users u
    where u.id = v_user_id;

    --------------------------------------------------------------------
    -- 3. Determine thread logic
    --------------------------------------------------------------------
    if p_parent_id is null then
        -- Root message
        v_thread_id := gen_random_uuid();
    else
        -- Find if parent is valid and ensure "no reply to reply"
        select (parent_id is null), thread_id into v_parent_is_root, v_thread_id
        from messages
        where id = p_parent_id;

        if not found then
            return jsonb_build_object(
                'status', 'error',
                'code', 'PARENT_NOT_FOUND',
                'message', 'Parent message does not exist.'
            );
        end if;

        if not v_parent_is_root then
            return jsonb_build_object(
                'status', 'error',
                'code', 'NESTED_THREAD_NOT_ALLOWED',
                'message', 'Cannot reply to a reply. Only one thread level is allowed.'
            );
        end if;
    end if;

    --------------------------------------------------------------------
    -- 4. Fetch & Decrypt Team Data Key
    --------------------------------------------------------------------
    
    -- A. Get Master Key from Vault
    select decrypted_secret into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    if v_master_key is null then
        return jsonb_build_object('status', 'error', 'code', 'CONFIG_ERROR', 'message', 'Master key not found in vault.');
    end if;

    -- B. Get Encrypted Team Key
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

    -- C. Decrypt the Team Data Key
    -- NOTE: using _bytea because the output v_data_key must be binary bytes
    v_data_key := extensions.pgp_sym_decrypt_bytea(
        v_enc_dk, 
        v_master_key
    );

    --------------------------------------------------------------------
    -- 5. Encrypt the message content
    --------------------------------------------------------------------
    -- NOTE: We use pgp_sym_encrypt (text input) because p_content is text.
    -- BUT, the key (v_data_key) is raw bytes, so we cast it to text or use it directly?
    -- Actually, standard pgcrypto expects the KEY to be text (a passphrase).
    -- Since v_data_key is raw bytes (high entropy), we must encode it to text 
    -- so pgcrypto can use it as a "passphrase".
    
    v_cipher := extensions.pgp_sym_encrypt(
        p_content, 
        encode(v_data_key, 'base64') -- Convert binary key to base64 for use as passphrase
    );

    --------------------------------------------------------------------
    -- 6. Insert message
    --------------------------------------------------------------------
    insert into messages (
        team_id,
        user_id,
        parent_id,
        thread_id,
        is_code_thread,
        content_ciphertext,
        content_hash
    ) values (
        p_team_id,
        v_user_id,
        p_parent_id,
        v_thread_id,
        p_is_code_thread,
        v_cipher,
        encode(extensions.digest(p_content, 'sha256'), 'base64')
    )
    returning id, created_at into v_message_id, v_created_at;

    --------------------------------------------------------------------
    -- 7. Return success JSON
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGE_CREATED',
        'message', jsonb_build_object(
        'message_id', v_message_id,
        'thread_id', v_thread_id,
        'parent_id', p_parent_id,
        'is_code_thread', p_is_code_thread,
        'content', p_content,
        'created_at', v_created_at,
        'u', jsonb_build_object(
                'user_id', v_user_id,
                'username', v_username,
                'display_name', v_display_name,
                'avatar_url', v_avatar_url
            )
    )
    );
end;$$;


ALTER FUNCTION "public"."create_message"("p_team_id" "uuid", "p_parent_id" "uuid", "p_content" "text", "p_is_code_thread" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_team_and_invite"("team_name" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
declare
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

    -- 5. Generate a unique 8-character invite code
    while not is_code_unique loop
        -- Generate a unique code (using MD5 of random data and timestamp, then take the first 8 chars)
        invite_code := substr(md5(random()::text || clock_timestamp()::text), 1, 8);

        begin
            -- Attempt to insert the invite code. If a unique_violation occurs, the loop repeats.
            insert into public.invites (team_id, code, created_by)
            values (new_team_id, invite_code, current_user_id);

            is_code_unique := true;

        exception
            when unique_violation then
                -- The generated code was not unique; try again.
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
    
end;
$$;


ALTER FUNCTION "public"."create_team_and_invite"("team_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_message_by_id"("p_team_id" "uuid", "p_message_id" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    AS $$


declare
    v_user_id uuid := auth.uid();

    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;

    v_row jsonb;
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
        select 1
        from team_members
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
    -- 3. load team encrypted data key
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

    select decrypted_secret
    into v_master_key
    from vault.decrypted_secrets
    where name = 'app_master_key_latest';

    if v_master_key is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'MISSING_MASTER_KEY',
            'message', 'Master key not available.'
        );
    end if;

    -- decrypt team data key
    v_data_key := pgp_sym_decrypt_bytea(
        v_enc_dk,
        v_master_key
    );

    --------------------------------------------------------------------
    -- 4. fetch + decrypt single message
    --------------------------------------------------------------------
    select jsonb_build_object(
        'message_id', m.id,
        'parent_id', m.parent_id,
        'thread_id', m.thread_id,
        'is_code_thread', m.is_code_thread,
        'content', convert_from(
            pgp_sym_decrypt_bytea(
                m.content_ciphertext,
                encode(v_data_key, 'base64')
            ),
            'utf8'
        ),
        'created_at', m.created_at,
        'u', jsonb_build_object(
            'user_id', m.user_id,
            'avatar_url', u.raw_user_meta_data ->> 'avatar_url',
            'display_name', u.raw_user_meta_data ->> 'display_name',
            'username', u.raw_user_meta_data ->> 'username'
        )
    )
    into v_row
    from messages m
    join auth.users u on u.id = m.user_id
    where m.id = p_message_id
      and m.team_id = p_team_id;

    if v_row is null then
        return jsonb_build_object(
            'status', 'error',
            'code', 'NOT_FOUND',
            'message', 'Message not found.'
        );
    end if;

    --------------------------------------------------------------------
    -- 5. wrap success
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGE_LOADED',
        'team_id', p_team_id,
        'message', v_row
    );
end;
$$;


ALTER FUNCTION "public"."get_message_by_id"("p_team_id" "uuid", "p_message_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_messages"("p_team_id" "uuid", "p_limit" integer DEFAULT NULL::integer, "p_offset" integer DEFAULT 0) RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$declare
    v_user_id uuid := auth.uid();

    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;

    v_rows jsonb := '[]'::jsonb;
    v_total_count int := 0; 
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
    -- 3. load team's encrypted data key
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

    select decrypted_secret as v_master_key into v_master_key
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
    -- 5. fetch + decrypt messages
    --------------------------------------------------------------------
    select jsonb_agg(
        jsonb_build_object(
            'message_id', m.id,
            'parent_id', m.parent_id,
            'thread_id', m.thread_id,
            'is_code_thread', m.is_code_thread,
            'content', convert_from(pgp_sym_decrypt_bytea(m.content_ciphertext, encode(v_data_key, 'base64')), 'utf8'),
            'created_at', m.created_at,
            'u', jsonb_build_object(
                'user_id', m.user_id,
                'avatar_url', u.raw_user_meta_data ->> 'avatar_url',
                'display_name', u.raw_user_meta_data ->> 'display_name',
                'username', u.raw_user_meta_data ->> 'username'
            )
        )

        order by m.created_at ASC
    )
    into v_rows
    from (
        select *
        from messages
        where team_id = p_team_id
        order by created_at DESC
        limit p_limit     
        offset coalesce(p_offset, 0)
    ) m
    join auth.users u on u.id = m.user_id;

    --------------------------------------------------------------------
    -- 6. wrap inside success JSONB
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'MESSAGES_LOADED',
        'team_id', p_team_id,
        'meta', jsonb_build_object(
            'total', v_total_count,
            'limit', p_limit,
            'offset', p_offset
        ),
        'messages', coalesce(v_rows, '[]'::jsonb)
    );
end;$$;


ALTER FUNCTION "public"."get_messages"("p_team_id" "uuid", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."join_team_with_code"("p_invite_code" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$declare
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
    where i.code = p_invite_code;

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
end;$$;


ALTER FUNCTION "public"."join_team_with_code"("p_invite_code" "text") OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."invites" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "team_id" "uuid" NOT NULL,
    "code" "text" NOT NULL,
    "created_by" "uuid" NOT NULL
);


ALTER TABLE "public"."invites" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."messages" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "team_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "parent_id" "uuid",
    "thread_id" "uuid",
    "is_code_thread" boolean DEFAULT false,
    "content_ciphertext" "bytea" NOT NULL,
    "content_hash" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."messages" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."team_data_keys" (
    "encrypted_data_key" "bytea" NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "team_id" "uuid" NOT NULL
);


ALTER TABLE "public"."team_data_keys" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."team_members" (
    "team_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "role" "text"
);


ALTER TABLE "public"."team_members" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."teams" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "created_by" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."teams" OWNER TO "postgres";


ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_code_key" UNIQUE ("code");



ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."messages"
    ADD CONSTRAINT "messages_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."team_data_keys"
    ADD CONSTRAINT "team_data_keys_pkey" PRIMARY KEY ("team_id");



ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_pkey" PRIMARY KEY ("team_id", "user_id");



ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_name_created_by_unique" UNIQUE ("name", "created_by");



ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON UPDATE CASCADE ON DELETE CASCADE;



ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "public"."teams"("id") ON UPDATE CASCADE ON DELETE CASCADE;



ALTER TABLE ONLY "public"."messages"
    ADD CONSTRAINT "messages_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "public"."teams"("id") ON UPDATE CASCADE ON DELETE CASCADE;



ALTER TABLE ONLY "public"."messages"
    ADD CONSTRAINT "messages_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."team_data_keys"
    ADD CONSTRAINT "team_data_keys_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "public"."teams"("id") ON UPDATE CASCADE ON DELETE CASCADE;



ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "public"."teams"("id") ON UPDATE CASCADE ON DELETE CASCADE;



ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON UPDATE CASCADE ON DELETE CASCADE;



ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON UPDATE CASCADE ON DELETE CASCADE;



ALTER TABLE "public"."invites" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."messages" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "team members can read messages" ON "public"."messages" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."team_members" "tm"
  WHERE (("tm"."team_id" = "messages"."team_id") AND ("tm"."user_id" = "auth"."uid"())))));



ALTER TABLE "public"."team_data_keys" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."team_members" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."teams" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "users can read own memberships" ON "public"."team_members" FOR SELECT USING (("user_id" = "auth"."uid"()));





ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";






ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."messages";



GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";

























































































































































GRANT ALL ON FUNCTION "public"."create_message"("p_team_id" "uuid", "p_parent_id" "uuid", "p_content" "text", "p_is_code_thread" boolean) TO "anon";
GRANT ALL ON FUNCTION "public"."create_message"("p_team_id" "uuid", "p_parent_id" "uuid", "p_content" "text", "p_is_code_thread" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_message"("p_team_id" "uuid", "p_parent_id" "uuid", "p_content" "text", "p_is_code_thread" boolean) TO "service_role";



GRANT ALL ON FUNCTION "public"."create_team_and_invite"("team_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_team_and_invite"("team_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_team_and_invite"("team_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_message_by_id"("p_team_id" "uuid", "p_message_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_message_by_id"("p_team_id" "uuid", "p_message_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_message_by_id"("p_team_id" "uuid", "p_message_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_messages"("p_team_id" "uuid", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."get_messages"("p_team_id" "uuid", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_messages"("p_team_id" "uuid", "p_limit" integer, "p_offset" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."join_team_with_code"("p_invite_code" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."join_team_with_code"("p_invite_code" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."join_team_with_code"("p_invite_code" "text") TO "service_role";


















GRANT ALL ON TABLE "public"."invites" TO "anon";
GRANT ALL ON TABLE "public"."invites" TO "authenticated";
GRANT ALL ON TABLE "public"."invites" TO "service_role";



GRANT ALL ON TABLE "public"."messages" TO "anon";
GRANT ALL ON TABLE "public"."messages" TO "authenticated";
GRANT ALL ON TABLE "public"."messages" TO "service_role";



GRANT ALL ON TABLE "public"."team_data_keys" TO "anon";
GRANT ALL ON TABLE "public"."team_data_keys" TO "authenticated";
GRANT ALL ON TABLE "public"."team_data_keys" TO "service_role";



GRANT ALL ON TABLE "public"."team_members" TO "anon";
GRANT ALL ON TABLE "public"."team_members" TO "authenticated";
GRANT ALL ON TABLE "public"."team_members" TO "service_role";



GRANT ALL ON TABLE "public"."teams" TO "anon";
GRANT ALL ON TABLE "public"."teams" TO "authenticated";
GRANT ALL ON TABLE "public"."teams" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";































drop extension if exists "pg_net";


