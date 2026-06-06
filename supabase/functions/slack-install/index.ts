// @ts-nocheck
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SLACK_CLIENT_ID = Deno.env.get("SLACK_CLIENT_ID")!;
const SLACK_CLIENT_SECRET = Deno.env.get("SLACK_CLIENT_SECRET")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

Deno.serve(async (req) => {
  const LINEBUZZ_PAGE_URL = Deno.env.get("LINEBUZZ_PAGE_URL");
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const [stateId, scheme] = (state || "").split(":");
  const finalScheme = scheme || "vscode";

  if (!code || !state) {
    return Response.redirect(`${LINEBUZZ_PAGE_URL}/slack-auth/?status=failed&error=missing_code_or_state`, 302);
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
      return Response.redirect(`${LINEBUZZ_PAGE_URL}/slack-auth/?status=failed&error=${encodeURIComponent(oauthData.error || "oauth_failed")}`, 302);
    }

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
      p_state: stateId,
      p_access_token: accessToken,
      p_channels: channelList
    });

    if (error || data?.status === "error") {
      console.log(error)
      return Response.redirect(`${LINEBUZZ_PAGE_URL}/slack-auth/?status=failed&error=${encodeURIComponent(data?.message || "verification_failed")}`, 302);
    }

    const redirectUri = `${finalScheme}://SpiralMemory.linebuzz/slack-auth-success`;
    return Response.redirect(`${LINEBUZZ_PAGE_URL}/slack-auth/?status=success&redirect_uri=${encodeURIComponent(redirectUri)}`, 302);

  } catch (err) {
    return Response.redirect(`${LINEBUZZ_PAGE_URL}/slack-auth/?status=failed&error=internal_error`, 302);
  }
});