SET check_function_bodies = false;
CREATE FUNCTION internal.handle_slack_notify_trigger()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  target_url TEXT;
  webhook_secret TEXT;
BEGIN
  SELECT value INTO target_url FROM internal.app_settings WHERE key = 'slack_webhook_url' LIMIT 1;

  SELECT decrypted_secret INTO webhook_secret FROM vault.decrypted_secrets WHERE name = 'slack_webhook_secret' LIMIT 1;

  IF target_url IS NULL OR webhook_secret IS NULL THEN
    RETURN NEW; 
  END IF;

  PERFORM net.http_post(
    url := target_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-webhook-secret', webhook_secret
    ),
    body := jsonb_build_object(
      'record', jsonb_build_object('id', new.id)
    )
  );

  RETURN NEW;
END;
$function$;
CREATE OR REPLACE TRIGGER "slack-notify-trigger" AFTER INSERT ON public.messages FOR EACH ROW WHEN (new.sync_to_slack = true) EXECUTE FUNCTION internal.handle_slack_notify_trigger();
