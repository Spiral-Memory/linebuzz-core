INSERT INTO auth.users (
  id,
  instance_id,
  aud,
  role,
  email,              
  encrypted_password, -- Keep NULL (No password login possible)
  email_confirmed_at, -- Set to NOW to avoid "Unverified" flags in UI
  raw_user_meta_data, 
  created_at,
  updated_at
)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000000', 
  'authenticated',
  'authenticated',
  'bot@slack.linebuzz', -- Your preferred bot email
  NULL,
  NOW(), 
  '{
    "username": "slack-bot",
    "display_name": "Slack Bot",
    "avatar_url": "https://a.slack-edge.com/80511/img/services/api_200.png"
  }',
  NOW(),
  NOW()
)
ON CONFLICT (id) DO UPDATE SET
  email = EXCLUDED.email,
  raw_user_meta_data = EXCLUDED.raw_user_meta_data,
  updated_at = NOW();


INSERT INTO internal.app_settings (key, value)
VALUES ('slack_bot_id', '00000000-0000-0000-0000-000000000001')
ON CONFLICT (key) 
DO UPDATE SET value = EXCLUDED.value;