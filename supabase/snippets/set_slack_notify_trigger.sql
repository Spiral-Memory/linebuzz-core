DROP TRIGGER IF EXISTS "slack-notify-trigger" ON public.messages;

CREATE TRIGGER "slack-notify-trigger"
  AFTER INSERT ON public.messages
  FOR EACH ROW
  WHEN (new.sync_to_slack = true)
  EXECUTE FUNCTION supabase_functions.http_request(
    '<YOUR-SLACK-NOTIFY-EDGE-FUNCTION-URL>',
    'POST',
    '{"content-type":"application/json","x-webhook-secret":"<YOUR-SLACK-WEBHOOK-SECRET>"}',
    '{}',
    '5000'
  );