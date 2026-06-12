DO $$
DECLARE
    secret_id uuid;
BEGIN
    SELECT id INTO secret_id FROM vault.decrypted_secrets WHERE name = 'app_master_key_latest';
    IF secret_id IS NOT NULL THEN
        PERFORM vault.update_secret(secret_id, '<YOUR_MASTER_KEY>');
    ELSE
        PERFORM vault.create_secret('<YOUR_MASTER_KEY>', 'app_master_key_latest', 'LineBuzz Team Master Key');
    END IF;
END $$;