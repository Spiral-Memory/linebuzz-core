INSERT INTO internal.app_settings (key, value)
VALUES (
    'slack_base_url', 
    '<YOUR_SLACK_OAUTH_URL>'
)
ON CONFLICT (key) 
DO UPDATE SET value = EXCLUDED.value;