CREATE TABLE public.messages (
  id                 uuid                     DEFAULT gen_random_uuid() NOT NULL,
  team_id            uuid                     NOT NULL,
  user_id            uuid                     NOT NULL,
  parent_id          uuid,
  thread_id          uuid,
  content_ciphertext bytea,
  content_hash       text,
  created_at         timestamp with time zone DEFAULT now(),
  quoted_id          uuid,
  sync_to_slack      boolean                  DEFAULT false NOT NULL,
  source             text                     DEFAULT 'app'::text,
  source_metadata    jsonb
);

CREATE INDEX idx_messages_pagination ON public.messages (team_id, created_at DESC, id DESC);

CREATE POLICY "team members can read messages" ON public.messages
  FOR SELECT
  USING ((EXISTS ( SELECT 1
   FROM public.team_members tm
  WHERE ((tm.team_id = messages.team_id) AND (tm.user_id = auth.uid())))));

ALTER TABLE public.messages
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.messages
  ADD CONSTRAINT messages_pkey PRIMARY KEY (id);

ALTER TABLE public.messages
  ADD CONSTRAINT messages_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);

ALTER TABLE public.messages
  ADD CONSTRAINT messages_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

GRANT ALL ON public.messages TO anon;

GRANT ALL ON public.messages TO authenticated;

GRANT ALL ON public.messages TO service_role;