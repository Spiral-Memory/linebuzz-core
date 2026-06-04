CREATE TABLE public.team_integration_tokens (
  team_id      uuid                     NOT NULL,
  provider     text                     NOT NULL,
  access_token bytea                    NOT NULL,
  created_at   timestamp with time zone DEFAULT now() NOT NULL,
  updated_at   timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE public.team_integration_tokens
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.team_integration_tokens
  ADD CONSTRAINT team_integration_tokens_pkey PRIMARY KEY (team_id, provider);

ALTER TABLE public.team_integration_tokens
  ADD CONSTRAINT team_integration_tokens_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

GRANT ALL ON public.team_integration_tokens TO service_role;
