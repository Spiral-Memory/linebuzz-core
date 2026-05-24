CREATE TABLE public.teams (
  id         uuid                     DEFAULT gen_random_uuid() NOT NULL,
  name       text                     NOT NULL,
  created_by uuid                     NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE public.teams
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.teams
  ADD CONSTRAINT teams_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE public.teams
  ADD CONSTRAINT teams_name_created_by_unique UNIQUE (name, created_by);

ALTER TABLE public.teams
  ADD CONSTRAINT teams_pkey PRIMARY KEY (id);

GRANT ALL ON public.teams TO anon;

GRANT ALL ON public.teams TO authenticated;

GRANT ALL ON public.teams TO service_role;