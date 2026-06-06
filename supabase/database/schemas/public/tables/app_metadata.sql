CREATE TABLE public.app_metadata (
  id boolean DEFAULT true PRIMARY KEY CHECK (id = true),
  min_client_version text NOT NULL
);

CREATE POLICY "Allow public read access to app_metadata" ON public.app_metadata
  FOR SELECT
  USING (true);

ALTER TABLE public.app_metadata
  ENABLE ROW LEVEL SECURITY;

GRANT ALL ON public.app_metadata TO anon;

GRANT ALL ON public.app_metadata TO authenticated;

GRANT ALL ON public.app_metadata TO service_role;
