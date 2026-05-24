CREATE TABLE public.team_data_keys (
  encrypted_data_key bytea                    NOT NULL,
  updated_at         timestamp with time zone DEFAULT now(),
  team_id            uuid                     NOT NULL
);

ALTER TABLE public.team_data_keys
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.team_data_keys
  ADD CONSTRAINT team_data_keys_pkey PRIMARY KEY (team_id);

ALTER TABLE public.team_data_keys
  ADD CONSTRAINT team_data_keys_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

GRANT ALL ON public.team_data_keys TO anon;

GRANT ALL ON public.team_data_keys TO authenticated;

GRANT ALL ON public.team_data_keys TO service_role;