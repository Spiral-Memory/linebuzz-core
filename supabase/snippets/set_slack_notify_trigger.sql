DO $$
DECLARE
    secret_id uuid;
BEGIN
    SELECT id INTO secret_id FROM vault.decrypted_secrets WHERE name = 'slack_webhook_secret';
    IF secret_id IS NOT NULL THEN
        PERFORM vault.update_secret(secret_id, '<YOUR-SLACK-WEBHOOK-SECRET>');
    ELSE
        PERFORM vault.create_secret('<YOUR-SLACK-WEBHOOK-SECRET>', 'slack_webhook_secret', 'Slack Notify Webhook Secret');
    END IF;
END $$;

INSERT INTO internal.app_settings (key, value)
VALUES ('slack_webhook_url', '<YOUR-SLACK-NOTIFY-EDGE-FUNCTION-URL>')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
