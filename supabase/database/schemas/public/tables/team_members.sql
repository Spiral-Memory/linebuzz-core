CREATE TABLE public.team_members (
  team_id uuid NOT NULL,
  user_id uuid NOT NULL,
  role    text
);

CREATE POLICY "users can read own memberships" ON public.team_members
  FOR SELECT
  USING ((user_id = auth.uid()));

ALTER TABLE public.team_members
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.team_members
  ADD CONSTRAINT team_members_pkey PRIMARY KEY (team_id, user_id);

ALTER TABLE public.team_members
  ADD CONSTRAINT team_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE public.team_members
  ADD CONSTRAINT team_members_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

GRANT ALL ON public.team_members TO anon;

GRANT ALL ON public.team_members TO authenticated;

GRANT ALL ON public.team_members TO service_role;