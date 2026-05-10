select cron.schedule(
  'cleanup-expired-oauth-states',
  '*/15 * * * *', -- Runs every 15 minutes
  $$ 
    delete from public.integration_oauth_states 
    where expires_at < now() 
  $$
);


create extension if not exists pg_cron;