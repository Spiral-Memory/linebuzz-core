SELECT vault.create_secret(
  '<YOUR-SLACK-WEBHOOK-SECRET>',
  'slack_webhook_secret',
  'Slack Notify Webhook Secret'
);

INSERT INTO internal.app_settings (key, value)
VALUES ('slack_webhook_url', '<YOUR-SLACK-NOTIFY-EDGE-FUNCTION-URL>')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
