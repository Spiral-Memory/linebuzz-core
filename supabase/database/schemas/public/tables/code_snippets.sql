CREATE TABLE public.code_snippets (
  id                 uuid                     DEFAULT gen_random_uuid() NOT NULL,
  team_id            uuid                     NOT NULL,
  user_id            uuid                     NOT NULL,
  message_id         uuid                     NOT NULL,
  remote_url         text                     NOT NULL,
  ref                text,
  commit_sha         text,
  file_path          text                     NOT NULL,
  start_line         integer                  NOT NULL,
  end_line           integer                  NOT NULL,
  snippet_ciphertext bytea                    NOT NULL,
  created_at         timestamp with time zone DEFAULT now(),
  snippet_hash       text,
  patch              bytea
);

CREATE INDEX idx_snippets_team_message ON public.code_snippets (team_id, message_id);

CREATE INDEX idx_snippets_team_url_path ON public.code_snippets (team_id, remote_url, file_path);

CREATE POLICY "team can read code snippets" ON public.code_snippets
  FOR SELECT
  USING ((EXISTS ( SELECT 1
   FROM public.team_members tm
  WHERE ((tm.team_id = code_snippets.team_id) AND (tm.user_id = auth.uid())))));

ALTER TABLE public.code_snippets
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.code_snippets
  ADD CONSTRAINT code_context_pkey PRIMARY KEY (id);

ALTER TABLE public.code_snippets
  ADD CONSTRAINT code_context_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);

ALTER TABLE public.code_snippets
  ADD CONSTRAINT code_context_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.messages(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE public.code_snippets
  ADD CONSTRAINT code_context_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

GRANT ALL ON public.code_snippets TO anon;

GRANT ALL ON public.code_snippets TO authenticated;

GRANT ALL ON public.code_snippets TO service_role;