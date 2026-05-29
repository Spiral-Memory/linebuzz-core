# **LineBuzz 🧵 Developer Collaboration in VS Code**

## **Overview 📘**

**The backend engine for LineBuzz.** This repository manages the database schema, real-time sync logic, and authentication policies.

## **Core Responsibilities ✨**

* **Data Infrastructure:** PostgreSQL schema and migrations managed via Supabase.
* **Real-time Engine:** Configuration for low-latency broadcast and presence channels.
* **Security (RLS):** Row-Level Security policies to ensure team data remains private.
* **Auth Gateway:** GitHub OAuth configuration and user session management.
* **Slack Integration Bridge:** Secure Deno Edge Functions enabling bi-directional message synchronization.

## **Technical Stack 🧰**

* **Backend:** Supabase (PostgreSQL, Real-time, Auth).
* **Language:** TypeScript / SQL.

## **Setup & Deployment 🛠️**

### **1. Prerequisites**

* [Supabase CLI](https://supabase.com/docs/guides/cli) installed.
* Docker (for local development).

### **2. Local Development**

**1. Clone the repository and start local Supabase:**

```bash
git clone https://github.com/Spiral-Memory/linebuzz-core.git
cd linebuzz-core

supabase start
```

**2. Serve Edge Functions:**

In a separate terminal, run:

```bash
supabase functions serve
```

For Slack functionality to work, populate the following variables in your local `supabase/functions/.env` file:
```env
SLACK_CLIENT_ID=<your-slack-client-id>
SLACK_CLIENT_SECRET=<your-slack-client-secret>
SLACK_SIGNING_SECRET=<your-slack-signing-secret>
X_WEBHOOK_SECRET=<your-webhook-secret>
```

**3. Initialize Database Secrets & Data:**

Run the following SQL queries in your local Supabase Studio SQL Editor to initialize the application master key and override the Slack OAuth redirect URL:

```sql
-- 1. Set the App Master Key (generate a key using `openssl rand -hex 16`):
SELECT vault.create_secret(
  '<YOUR_GENERATED_KEY>',
  'app_master_key_latest',
  'LineBuzz Team Master Key'
);

-- 2. Configure the Slack OAuth Redirect Base URL (if different from default http://localhost:3000):
INSERT INTO internal.app_settings (key, value)
VALUES ('slack_base_url', 'http://localhost:3000') -- Replace with your local/production URL
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
```

> [!NOTE]
> * BIP-39 seed words are automatically populated via the `supabase/seed.sql` script when resetting the database (`supabase db reset`), so manual seeding is not required.
> * These SQL initialization scripts are also available as individual files in the `supabase/snippets/` directory (`set_master_key.sql` and `set_slack_oauth_url.sql`).

### **3. Database Migrations**

We follow a **declarative schema** approach using Supabase's `pgdelta` features. The database schema's source of truth is defined as SQL files under `supabase/database/schemas/`. 

To make database changes:

1. **Modify the declarative schema files** directly in the `supabase/database/schemas/` directory (e.g., updating/creating SQL files under `public/tables/` or `public/functions/`).
   * *Do not* make changes directly via the Supabase UI / dashboard.
   * *Do not* write your own migrations from scratch in `supabase/migrations/`.

2. **Generate and apply the migration locally** by running:
   ```bash
   supabase db schema declarative sync
   ```
   This command compares your declarative schema files against your current local database, prompts you for a migration name, automatically generates a versioned migration under `supabase/migrations/`, and applies it to your local database.

3. **Deploy to production / remote database**:
   ```bash
   supabase db push
   ```

> [!TIP]
> If your local database gets into an inconsistent state or you want to rebuild it from scratch, you can still run `supabase db reset`.

## **Contributing 🤝**

Contributions are always welcome.
Fork the repository, open it in your preferred editor, and use the Supabase CLI to manage migrations.
For significant updates, open an issue first to discuss your approach.