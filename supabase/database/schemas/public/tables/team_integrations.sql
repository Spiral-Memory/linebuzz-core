CREATE TABLE public.team_integrations (
  team_id      uuid                     NOT NULL,
  provider     text                     NOT NULL,
  access_token bytea                    NOT NULL,
  settings     jsonb                    DEFAULT '{}'::jsonb,
  created_at   timestamp with time zone DEFAULT now(),
  updated_at   timestamp with time zone DEFAULT now()
);

CREATE POLICY "Team members can view their own integrations" ON public.team_integrations
  FOR SELECT
  TO authenticated
  USING ((EXISTS ( SELECT 1
   FROM public.team_members
  WHERE ((team_members.team_id = team_integrations.team_id) AND (team_members.user_id = auth.uid())))));

ALTER TABLE public.team_integrations
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.team_integrations
  ADD CONSTRAINT team_integrations_pkey PRIMARY KEY (team_id, PROVIDER);

ALTER TABLE public.team_integrations
  ADD CONSTRAINT team_integrations_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

GRANT ALL ON public.team_integrations TO anon;

GRANT ALL ON public.team_integrations TO authenticated;

GRANT ALL ON public.team_integrations TO service_role;