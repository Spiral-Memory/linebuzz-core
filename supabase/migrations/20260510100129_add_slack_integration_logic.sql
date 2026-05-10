create extension if not exists "pg_net" with schema "extensions";


  create table "internal"."app_settings" (
    "key" text not null,
    "value" text not null
      );



  create table "public"."integration_oauth_states" (
    "id" uuid not null default gen_random_uuid(),
    "provider" text not null,
    "user_id" uuid,
    "team_id" uuid not null,
    "expires_at" timestamp with time zone default (now() + '00:15:00'::interval),
    "created_at" timestamp with time zone default now()
      );


alter table "public"."integration_oauth_states" enable row level security;


  create table "public"."team_integrations" (
    "team_id" uuid not null,
    "provider" text not null,
    "access_token" bytea not null,
    "settings" jsonb default '{}'::jsonb,
    "created_at" timestamp with time zone default now(),
    "updated_at" timestamp with time zone default now()
      );


alter table "public"."team_integrations" enable row level security;

CREATE UNIQUE INDEX app_settings_pkey ON internal.app_settings USING btree (key);

CREATE UNIQUE INDEX integration_oauth_states_pkey ON public.integration_oauth_states USING btree (id);

CREATE UNIQUE INDEX team_integrations_pkey ON public.team_integrations USING btree (team_id, provider);

alter table "internal"."app_settings" add constraint "app_settings_pkey" PRIMARY KEY using index "app_settings_pkey";

alter table "public"."integration_oauth_states" add constraint "integration_oauth_states_pkey" PRIMARY KEY using index "integration_oauth_states_pkey";

alter table "public"."team_integrations" add constraint "team_integrations_pkey" PRIMARY KEY using index "team_integrations_pkey";

alter table "public"."integration_oauth_states" add constraint "integration_oauth_states_user_id_fkey" FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE not valid;

alter table "public"."integration_oauth_states" validate constraint "integration_oauth_states_user_id_fkey";

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.disconnect_slack(p_team_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
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
    -- 3. Delete Integration
    --------------------------------------------------------------------
    -- Removes the Slack configuration, tokens, and settings for this team.
    delete from public.team_integrations
    where team_id = p_team_id and provider = 'slack';

    --------------------------------------------------------------------
    -- 4. Return Success
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'DISCONNECTED',
        'message', 'Slack integration removed successfully.'
    );
end;
$function$
;

CREATE OR REPLACE FUNCTION public.get_slack_install_url(p_team_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
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
$function$
;

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
        ti.access_token, 
        ti.settings->>'active_channel_id'
    into 
        v_team_id, 
        v_user_id, 
        v_msg_ciphertext, 
        v_token_ciphertext, 
        v_slack_channel_id
    from public.messages m
    join public.team_integrations ti on m.team_id = ti.team_id
    where m.id = p_message_id and ti.provider = 'slack';

    if not found then
        return jsonb_build_object(
            'status', 'error', 
            'code', 'NOT_FOUND',
            'message', 'Message or Slack integration not found.'
        );
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
        raw_user_meta_data ->> 'username'
    into 
        v_display_name, 
        v_username
    from auth.users where id = v_user_id;

    --------------------------------------------------------------------
    -- 5. Final Decryption and Assembly
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'payload', jsonb_build_object(
            'channel_id', v_slack_channel_id,
            'user_name', coalesce(v_username, v_display_name, 'Buzz Member'),
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
end;$function$
;

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
    
    -- Encryption Variables
    v_enc_dk bytea;
    v_data_key bytea;
    v_master_key text;
    v_encrypted_token bytea;
begin
    --------------------------------------------------------------------
    -- 1. Atomic State Verification & "Burn" (Error: INVALID_STATE)
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
    -- 2. Final Admin Membership Check (Error: FORBIDDEN)
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
    -- 3. Encryption Setup (Error: CONFIG_ERROR)
    --------------------------------------------------------------------
    -- Fetch the team's data key
    select encrypted_data_key into v_enc_dk
    from public.team_data_keys
    where team_id = v_team_id;

    -- Fetch the master key from vault
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

    -- Decrypt the data key and then encrypt the Slack token
    v_data_key := extensions.pgp_sym_decrypt_bytea(v_enc_dk, v_master_key);
    v_encrypted_token := extensions.pgp_sym_encrypt_bytea(
        p_access_token::bytea, 
        encode(v_data_key, 'base64')
    );

    --------------------------------------------------------------------
    -- 4. Upsert Integration Record (Success: CONNECTED)
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
            'channels', p_channels,        -- Store the fetched list
            'active_channel_id', null      -- Default to no active channel
        )
    )
    on conflict (team_id, provider) 
    do update set 
        access_token = excluded.access_token,
        settings = excluded.settings,      -- Update channel list on re-auth
        updated_at = now();

    --------------------------------------------------------------------
    -- 5. Return Success
    --------------------------------------------------------------------
    return jsonb_build_object(
        'status', 'success',
        'code', 'SLACK_CONNECTED',
        'team_id', v_team_id,
        'message', 'Slack integration successfully completed.'
    );
end;
$function$
;

CREATE OR REPLACE FUNCTION public.set_slack_channel(p_team_id uuid, p_channel_id text)
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
end;$function$
;


  create policy "Team members can view their own integrations"
  on "public"."team_integrations"
  as permissive
  for select
  to authenticated
using ((EXISTS ( SELECT 1
   FROM public.team_members
  WHERE ((team_members.team_id = team_integrations.team_id) AND (team_members.user_id = auth.uid())))));


CREATE TRIGGER "slack-notify-trigger" AFTER INSERT ON public.messages FOR EACH ROW EXECUTE FUNCTION supabase_functions.http_request('http://host.docker.internal:54321/functions/v1/slack-notify', 'POST', '{"content-type":"application/json","x-webhook-secret":"test_secret"}', '{}', '5000');


