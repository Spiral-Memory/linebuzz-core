INSERT INTO public.app_metadata (id, min_client_version)
VALUES (true, '<MIN_SUPPORTED_CLIENT_VERSION>')
ON CONFLICT (id)
DO UPDATE SET
    min_client_version = EXCLUDED.min_client_version;