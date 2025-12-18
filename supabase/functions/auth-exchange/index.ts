// @ts-nocheck
import { createClient } from 'npm:@supabase/supabase-js@2';
Deno.serve(async (req)=>{
  try {
    const body = await req.json().catch(()=>({}));
    const githubToken = body.githubToken;
    if (!githubToken) return new Response(JSON.stringify({
      error: 'missing_github_token'
    }), {
      status: 400
    });
    const url = Deno.env.get('SUPABASE_URL');
    const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!url || !key) return new Response(JSON.stringify({
      error: 'server_config'
    }), {
      status: 500
    });
    const supabase = createClient(url, key, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });
    const ghRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${githubToken}`
      }
    });
    if (!ghRes.ok) return new Response(JSON.stringify({
      error: 'github_fetch_failed'
    }), {
      status: 502
    });
    const ghUser = await ghRes.json();
    let email = ghUser.email;
    if (!email) {
      const emailsRes = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${githubToken}`
        }
      });
      if (emailsRes.ok) {
        const list = await emailsRes.json();
        if (Array.isArray(list) && list.length > 0) {
          email = list.find((e)=>e.primary)?.email || list[0].email;
        }
      }
    }
    if (!email) return new Response(JSON.stringify({
      error: 'no_email'
    }), {
      status: 400
    });
    const metadata = {
      display_name: ghUser.name || null,
      username: ghUser.login || null,
      avatar_url: ghUser.avatar_url || null
    };
    const { data, error } = await supabase.auth.admin.generateLink({
      type: 'magiclink',
      email,
      data: metadata
    });
    if (error) {
      return new Response(JSON.stringify({
        error: 'supabase_error'
      }), {
        status: 500
      });
    }
    const otp = data?.properties?.email_otp;
    return new Response(JSON.stringify({
      supabase_email: email,
      supabase_otp: otp
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  } catch (e) {
    console.error('unhandled error', e);
    return new Response(JSON.stringify({
      error: 'internal_error'
    }), {
      status: 500
    });
  }
});
