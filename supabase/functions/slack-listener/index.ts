// @ts-nocheck
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { encodeHex } from "https://deno.land/std@0.207.0/encoding/hex.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SLACK_SIGNING_SECRET = Deno.env.get("SLACK_SIGNING_SECRET") || Deno.env.get("SLACK_CLIENT_SECRET")!;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

async function verifySignature(req: Request, rawBody: string): Promise<boolean> {
  const sig = req.headers.get("x-slack-signature");
  const ts = req.headers.get("x-slack-request-timestamp");
  if (!sig || !ts || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SLACK_SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const hash = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`v0:${ts}:${rawBody}`));
  return `v0=${encodeHex(hash)}` === sig;
}

Deno.serve(async (req) => {
  try {
    const rawBody = await req.text();

    // 1. Authenticate Request Origin
    if (!(await verifySignature(req, rawBody))) {
      console.error("Invalid Slack signature");
      return new Response("Unauthorized Signature", { status: 401 });
    }

    const body = JSON.parse(rawBody);

    // 2. Handle Slack URL Verification Challenge
    if (body.type === "url_verification") {
      console.log("Slack URL verification challenge");
      return Response.json({ challenge: body.challenge });
    }

    // 3. Process Incoming Chat Messages
    const ev = body.event;
    console.log("Slack event:", ev);
    if (ev?.type === "message" && ev.text && ev.user && !ev.bot_id && !ev.subtype) {
      // Find connected team ID
      const { data: int, error: intError } = await supabase
        .from("team_integrations")
        .select("team_id")
        .eq("provider", "slack")
        .eq("settings->>active_channel_id", ev.channel)
        .maybeSingle();

      if (intError) {
        console.error("Error fetching team integration:", intError);
      }

      console.log("Found integration:", int);

      if (int) {
        // Retrieve decrypted Slack token securely
        const { data: token, error: tokenError } = await supabase.rpc("get_slack_token", { p_team_id: int.team_id });

        if (tokenError) {
          console.error("Error invoking get_slack_token RPC:", tokenError);
        }

        if (token) {
          console.log("Decrypted Slack token retrieved successfully");
          // Retrieve sender details from Slack API
          const slackRes = await fetch(`https://slack.com/api/users.info?user=${ev.user}`, {
            headers: { Authorization: `Bearer ${token}` }
          }).then(res => res.json());

          if (!slackRes.ok) {
            console.error("Error retrieving user info from Slack API:", slackRes.error);
          }

          const profile = slackRes.user?.profile;
          const name = profile?.display_name || profile?.real_name || slackRes.user?.name || "Slack User";
          const avatar = profile?.image_48 || profile?.image_72 || "";

          // Handle thread replies and quoted messages
          let quotedId: string | null = null;
          let parentId: string | null = null;

          if (ev.thread_ts) {
            // Case A: This is a thread reply.
            const { data: parentMsg } = await supabase
              .from("messages")
              .select("id")
              .eq("source_metadata->>slack_event_ts", ev.thread_ts)
              .maybeSingle();

            if (parentMsg) {
              parentId = parentMsg.id;
              quotedId = parentMsg.id;
              console.log("Mapped Slack thread reply to Linebuzz quote. Parent message:", parentId);
            }
          } else {
            // Case B: This is a normal message. Look for quote attachments if any.
            const quotedAttachment = ev.attachments?.find((att: any) => att.from_url);

            if (quotedAttachment?.from_url) {
              const match = quotedAttachment.from_url.match(/archives\/[^\/]+\/p(\d+)/);
              if (match) {
                const rawTs = match[1];
                const slackEventTs = `${rawTs.slice(0, 10)}.${rawTs.slice(10)}`;

                const { data: quotedMsg } = await supabase
                  .from("messages")
                  .select("id")
                  .eq("source_metadata->>slack_event_ts", slackEventTs)
                  .maybeSingle();

                if (quotedMsg) {
                  quotedId = quotedMsg.id;
                }
              }
            }
          }

          // Securely encrypt and insert bridged message
          const { data: insertRes, error: insertError } = await supabase.rpc("insert_slack_message", {
            p_team_id: int.team_id,
            p_content: ev.text,
            p_source_metadata: {
              display_name: name,
              username: name,
              avatar_url: avatar,
              slack_user_id: ev.user,
              slack_event_id: body.event_id,
              slack_event_ts: ev.event_ts
            },
            p_quoted_id: quotedId || undefined,
            p_parent_id: parentId || undefined
          });

          if (insertError) {
            console.error("Error invoking insert_slack_message RPC:", insertError);
          } else {
            console.log("Successfully inserted bridged message:", insertRes);
          }
        } else {
          console.warn("No Slack token retrieved for team:", int.team_id);
        }
      } else {
        console.warn("No active Slack integration found for channel:", ev.channel);
      }
    }

    return new Response("OK", { status: 200 });
  } catch (err) {
    console.error("Listener error:", err.message);
    return new Response(err.message, { status: 500 });
  }
});