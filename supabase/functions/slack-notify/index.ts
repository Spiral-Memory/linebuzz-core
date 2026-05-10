// @ts-nocheck
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const WEBHOOK_SECRET = Deno.env.get('X_WEBHOOK_SECRET')
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')

Deno.serve(async (req) => {
    try {
        const incomingSecret = req.headers.get('x-webhook-secret')
        if (incomingSecret !== WEBHOOK_SECRET) {
            return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 })
        }

        const { record } = await req.json()
        if (!record?.id) {
            return new Response(JSON.stringify({ error: 'No message ID provided' }), { status: 400 })
        }

        const supabase = createClient(SUPABASE_URL!, SUPABASE_SERVICE_ROLE_KEY!)

        const { data, error: rpcError } = await supabase
            .rpc('get_slack_payload', { p_message_id: record.id })

        if (rpcError || data?.status === 'error') {
            console.error('RPC Error:', rpcError || data?.message)
            return new Response(JSON.stringify({ error: 'Failed to retrieve secure payload' }), { status: 500 })
        }

        const { payload } = data

        const messageBody = {
            channel: payload.channel_id,
            blocks: [
                {
                    type: "section",
                    text: {
                        type: "mrkdwn",
                        text: `*${payload.user_name}*\n${payload.decrypted_message}`
                    }
                }
            ]
        }
        const slackHeaders = {
            'Authorization': `Bearer ${payload.decrypted_token}`,
            'Content-Type': 'application/json',
        }

        let slackRes = await fetch('https://slack.com/api/chat.postMessage', {
            method: 'POST',
            headers: slackHeaders,
            body: JSON.stringify(messageBody),
        })

        let slackData = await slackRes.json()

        if (!slackData.ok && slackData.error === 'not_in_channel') {
            console.log(`Bot not in channel ${payload.channel_id}. Attempting to join...`)

            const joinRes = await fetch('https://slack.com/api/conversations.join', {
                method: 'POST',
                headers: slackHeaders,
                body: JSON.stringify({ channel: payload.channel_id }),
            })

            const joinData = await joinRes.json()

            if (joinData.ok) {
                console.log('Successfully joined channel')
                slackRes = await fetch('https://slack.com/api/chat.postMessage', {
                    method: 'POST',
                    headers: slackHeaders,
                    body: JSON.stringify(messageBody),
                })
                slackData = await slackRes.json()
            } else {
                console.error('Slack Join Error:', joinData.error)
            }
        }

        if (!slackData.ok) {
            console.error('Slack API Error:', slackData.error)
            return new Response(JSON.stringify({ error: `Slack delivery failed: ${slackData.error}` }), { status: 500 })
        }
        console.log('Slack delivery successful')
        return new Response(JSON.stringify({ status: 'success' }), { status: 200 })

    } catch (err) {
        console.error('Unexpected Error:', err.message)
        return new Response(JSON.stringify({ error: err.message }), { status: 500 })
    }
})