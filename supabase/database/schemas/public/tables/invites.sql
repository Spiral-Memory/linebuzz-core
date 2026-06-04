CREATE TABLE public.invites (
  id         uuid DEFAULT gen_random_uuid() NOT NULL,
  team_id    uuid NOT NULL,
  code       text NOT NULL,
  created_by uuid NOT NULL,
  encrypted_code bytea
);

ALTER TABLE public.invites
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.invites
  ADD CONSTRAINT invites_code_key UNIQUE (code);

ALTER TABLE public.invites
  ADD CONSTRAINT invites_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE public.invites
  ADD CONSTRAINT invites_pkey PRIMARY KEY (id);

ALTER TABLE public.invites
  ADD CONSTRAINT invites_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

GRANT ALL ON public.invites TO anon;

GRANT ALL ON public.invites TO authenticated;

GRANT ALL ON public.invites TO service_role;