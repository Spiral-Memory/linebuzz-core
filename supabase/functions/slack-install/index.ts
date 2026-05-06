// @ts-nocheck
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SLACK_CLIENT_ID = Deno.env.get("SLACK_CLIENT_ID")!;
const SLACK_CLIENT_SECRET = Deno.env.get("SLACK_CLIENT_SECRET")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response("Error: Missing code or state parameters.", { status: 400 });
  }

  try {
    const slackRes = await fetch("https://slack.com/api/oauth.v2.access", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: SLACK_CLIENT_ID,
        client_secret: SLACK_CLIENT_SECRET,
        code: code,
      }),
    });

    const oauthData = await slackRes.json();

    if (!oauthData.ok) {
      return new Response(`Slack OAuth Error: ${oauthData.error}`, { status: 400 });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const { data, error } = await supabase.rpc("install_slack", {
      p_state: state,
      p_access_token: oauthData.access_token,
    });

    if (error || data?.status === "error") {
      console.error("Handshake Failed:", error || data?.message);
      return new Response(data?.message || "Verification failed. Please try again.", { status: 403 });
    }

    
    return new Response("Success! Linebuzz is now connected to Slack. You can safely close this tab and return to your IDE to select your sync channel.", {
      status: 200,
      headers: { "Content-Type": "text/plain" }
    });

  } catch (err) {
    console.error("System Exception:", err);
    return new Response("Internal Server Error", { status: 500 });
  }
});