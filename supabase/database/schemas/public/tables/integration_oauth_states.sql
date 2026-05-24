CREATE TABLE public.integration_oauth_states (
  id         uuid                     DEFAULT gen_random_uuid() NOT NULL,
  provider   text                     NOT NULL,
  user_id    uuid,
  team_id    uuid                     NOT NULL,
  expires_at timestamp with time zone DEFAULT (now() + '00:15:00'::interval),
  created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.integration_oauth_states
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.integration_oauth_states
  ADD CONSTRAINT integration_oauth_states_pkey PRIMARY KEY (id);

ALTER TABLE public.integration_oauth_states
  ADD CONSTRAINT integration_oauth_states_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;

GRANT ALL ON public.integration_oauth_states TO anon;

GRANT ALL ON public.integration_oauth_states TO authenticated;

GRANT ALL ON public.integration_oauth_states TO service_role;