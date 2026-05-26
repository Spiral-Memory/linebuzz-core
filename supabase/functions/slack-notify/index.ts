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

        // Handle quoted message
        let finalMessage = payload.decrypted_message
        if (payload.quoted_message) {
            const quoteLines = payload.quoted_message.content
                .split('\n')
                .map((line: string) => `> ${line}`)
                .join('\n')
            finalMessage += `\n\n> *${payload.quoted_message.user_name}*\n${quoteLines}`
        }

        // Handle code snippets
        if (payload.code_snippets && payload.code_snippets.length > 0) {
            for (const snip of payload.code_snippets) {
                const extension = snip.file_path.split('.').pop() || ''

                let cleanUrl = snip.remote_url ? snip.remote_url.trim() : ''
                let githubLink = ''
                if (cleanUrl) {
                    if (cleanUrl.startsWith('git@')) {
                        cleanUrl = cleanUrl.replace(':', '/').replace('git@', 'https://')
                    }
                    if (cleanUrl.endsWith('.git')) {
                        cleanUrl = cleanUrl.slice(0, -4)
                    }
                    githubLink = `<${cleanUrl}/blob/main/${snip.file_path}#L${snip.start_line}-L${snip.end_line}|Open on GitHub>`
                }

                const vscodeLink = `<vscode://SpiralMemory.linebuzz/open?filePath=${encodeURIComponent(snip.file_path)}&startLine=${snip.start_line}&endLine=${snip.end_line}|Open in VS Code>`
                const links = [vscodeLink, githubLink].filter(Boolean).join(' | ')

                finalMessage += `\n\n*Ref: ${snip.file_path}:${snip.start_line}-${snip.end_line})*\n\`\`\`${extension}\n${snip.content}\n\`\`\`\n${links}`
            }
        }

        const messageBody: any = {
            channel: payload.channel_id,
            username: payload.user_name,
            icon_url: payload.user_avatar_url || undefined,
            blocks: [
                {
                    type: "section",
                    text: {
                        type: "mrkdwn",
                        text: finalMessage
                    }
                },
                {
                    type: "context",
                    elements: [
                        {
                            type: "mrkdwn",
                            text: "via _Linebuzz_"
                        }
                    ]
                }
            ]
        }

        if (payload.parent_slack_ts) {
            messageBody.thread_ts = payload.parent_slack_ts
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

        // Update the original message's source_metadata to store the Slack timestamp (ts)
        if (slackData.ts) {
            console.log('Updating message source_metadata with Slack ts:', slackData.ts)
            const updatedMetadata = {
                ...(record.source_metadata || {}),
                slack_event_ts: slackData.ts
            }
            await supabase
                .from('messages')
                .update({
                    source_metadata: updatedMetadata
                })
                .eq('id', record.id)
        }

        return new Response(JSON.stringify({ status: 'success' }), { status: 200 })

    } catch (err) {
        console.error('Unexpected Error:', err.message)
        return new Response(JSON.stringify({ error: err.message }), { status: 500 })
    }
})