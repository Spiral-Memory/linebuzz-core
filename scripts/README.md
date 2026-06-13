# **LineBuzz 🧵 Self-Hosted & Cloud Deployment Guide**

## **Overview 📘**

The **LineBuzz Core Setup & Deployment Suite** automates database provisioning, schema migrations, database seeding, and configuration for local self-hosted environments and remote/cloud databases.

It automatically handles:
* Local self-hosted Supabase spin-up via Docker.
* Environment file (`.env`) generation and sync.
* Application of database schemas and migrations.
* Secret configuration (App Master Key, Slack details).
* Deno Edge Function deployment.

## **Prerequisites 🛠️**

Ensure you have the following installed on your target deployment machine:
* **Node.js** (v18+) and **npm**
* **Docker** (Required for local self-hosted Supabase)
* **Git** (Required for sparse-cloning Supabase)

## **Setup 🚀**

Clone the repository and navigate into it:
```bash
git clone -b main https://github.com/Spiral-Memory/linebuzz-core.git
cd linebuzz-core
```

Choose the scenario below that matches your deployment target:

### **A. Spin Up a New Local Self-Hosted Supabase Instance**

> [!IMPORTANT]
> * **Linux Only:** This automated setup path is Linux-only. On macOS/Windows, follow the [Supabase Docker Guide](https://supabase.com/docs/guides/self-hosting/docker) to install manually.
> * **Existing Database?** Skip directly to **[Section B](#b-deploy-schema-to-an-existing-database-locally-hosted-external-or-supabase-cloud)**.
> * **Port Conflict:** Ensure host port `5432` is free. Stop any local Postgres (`sudo systemctl stop postgresql`) or change `POSTGRES_PORT` in `supabase-project/.env`.

#### **Execution Steps:**
1. Run setup inside the `scripts/` folder:
   ```bash
   # Linux
   chmod +x setup.sh && ./setup.sh
   ```
2. Select **Choice 1** when prompted.
3. Enter the path where the Supabase project files should be cloned (defaults to `~/supabase-project`).
4. Set your service URLs (default `http://localhost:8000`) and connection pooler tenant ID.

### **B. Deploy Schema to an Existing Database (locally hosted, external, or Supabase Cloud)**
Use this option if you already have a running Supabase instance (such as a Supabase Cloud project, an external or locally self-hosted server) and just want to deploy the LineBuzz schema.

> [!NOTE]
> **Local CLI Development:** If you are using the local Supabase CLI (`supabase start`), do not use this script to deploy functions. Instead, follow the **Development** section in the main [README.md](../README.md). This setup suite is intended only for self-hosted Docker and Supabase Cloud environments.

#### **Cloud Deployment Prerequisites (Supabase Cloud)**
Before running the setup script, ensure you:
1. **Authenticate the CLI:** Run `npx supabase login` to sign in.
2. **Find Project Ref:** Locate your **20-character Project Reference ID** (e.g., `abcd1234efgh5678ijkl`) in your project dashboard URL.
3. **Database Connection URL:** Obtain your connection string from **Project Dashboard > Connect > Direct URI** (replace the password placeholder with your actual database password).

#### **Local Self-Hosted Prerequisites (Docker)**
Before running the setup script, ensure:
1. **Service is Running:** Your local self-hosted docker compose is active.
2. **Connection URL Ready:** Note your local postgres connection string (default self-hosted: `postgresql://postgres:<password>@localhost:5432/postgres`).

#### **Execution Steps:**
1. Run setup inside the `scripts/` folder:
   ```bash
   # Linux
   chmod +x setup.sh && ./setup.sh

   # Windows (PowerShell)
   ./setup.ps1
   ```
2. Select **Choice 2** when prompted and follow the on-screen instructions.

## **Environment Configurations ⚙️**

The deployment settings are configured in `scripts/.env`.

### **Key Configuration Options**

* **`DEPLOYMENT_TYPE`**: Either `local` (self-hosted Docker) or `cloud` (Supabase Cloud).
* **`DATABASE_URL`**: The database connection string used for migrations (required for both self-hosted Docker and Supabase Cloud deployments).
* **`APP_MASTER_KEY`**: A 32-character hex key used as the root security credential in the database (encrypting/decrypting Slack integration OAuth tokens, generating team invite codes, and validating workspace member permissions).
  * *Generation & Storage:* If empty or not defined, the setup script will automatically generate a secure random 32-character hex key and save it to `.env` on the first run.
  * *Warning:* **Keep this key safe.** Changing it later breaks decryption of existing Slack credentials and invite codes.
* **`MIN_CLIENT_VERSION`**: The minimum supported VS Code extension version (e.g., `0.3.0`).
* **`SLACK_*`**: Settings for bi-directional Slack message synchronization (`SLACK_BASE_URL`, `SLACK_WEBHOOK_SECRET`, `SLACK_NOTIFY_URL`).
* **Edge Function Secrets**: Secrets synced directly to Deno Edge Functions (`SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `SLACK_SIGNING_SECRET`, `X_WEBHOOK_SECRET`, `LINEBUZZ_PAGE_URL`).

## **Edge Functions & Verification 🕵️**

When using Option 1 (Local Self-Hosted), the script copies your Deno Edge Functions and environment variables directly into the self-hosted Docker volumes. 

* **Verify loaded secrets:** To verify that your Edge Function secrets are correctly loaded into the self-hosted runtime, run:
  ```bash
  docker exec supabase-edge-functions env
  ```
* **Local environment isolation:** The setup automatically ignores local `.env` files inside your local `supabase/functions/` folder during deployment. Secrets must be configured in `scripts/.env`.
