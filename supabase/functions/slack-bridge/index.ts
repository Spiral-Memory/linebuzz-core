// @ts-nocheck
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"

console.log("Slack Bridge function is live!");

serve(async (req) => {
  try {
    const body = await req.json();
    console.log("Body", body)

    if (body.type === "url_verification") {
      return new Response(JSON.stringify({ challenge: body.challenge }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (body.event) {
      const { type, text, user, bot_id } = body.event;

      if (bot_id) {
        return new Response("Bot message ignored", { status: 200 });
      }

      console.log(`[Slack Event] Type: ${type} | User: ${user} | Text: ${text}`);

    }

    return new Response("Event Received", { status: 200 });

  } catch (error) {
    console.error("Error processing request:", error.message);
    return new Response(JSON.stringify({ error: error.message }), { 
      status: 500,
      headers: { "Content-Type": "application/json" } 
    });
  }
})