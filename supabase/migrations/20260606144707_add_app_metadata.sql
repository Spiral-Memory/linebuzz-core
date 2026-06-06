CREATE TABLE public.app_metadata (id boolean DEFAULT true NOT NULL, min_client_version text NOT NULL);
ALTER TABLE public.app_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_metadata ADD CONSTRAINT app_metadata_id_check CHECK (id = true);
ALTER TABLE public.app_metadata ADD CONSTRAINT app_metadata_pkey PRIMARY KEY (id);
CREATE POLICY "Allow public read access to app_metadata" ON public.app_metadata FOR SELECT USING (true);
