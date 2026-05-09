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
    return new Response("Error: Missing code or state.", { status: 400 });
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
    if (!oauthData.ok) return new Response(`OAuth Error: ${oauthData.error}`, { status: 400 });

    const accessToken = oauthData.access_token;

    const channelsRes = await fetch("https://slack.com/api/conversations.list?types=public_channel,private_channel", {
      headers: { "Authorization": `Bearer ${accessToken}` }
    });
    
    const channelsData = await channelsRes.json();
    
    const channelList = (channelsData.channels || []).map((c: any) => ({
      id: c.id,
      name: c.name,
    }));

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const { data, error } = await supabase.rpc("install_slack", {
      p_state: state,
      p_access_token: accessToken,
      p_channels: channelList
    });

    if (error || data?.status === "error") {
      return new Response(data?.message || "Verification failed.", { status: 403 });
    }

    return new Response("Success! Linebuzz is now connected to Slack. You can safely close this tab and return to your IDE to select your sync channel.", {
      status: 200,
      headers: { "Content-Type": "text/plain" }
    });

  } catch (err) {
    return new Response("Internal Server Error", { status: 500 });
  }
});