# **LineBuzz 🧵 Self-Hosted & Cloud Deployment Guide**

## **Overview 📘**

The **LineBuzz Core Setup & Deployment Suite** automates database provisioning, schema migrations, database seeding, and configuration for local self-hosted environments and remote/cloud databases.

It automatically handles:
* Local self-hosted Supabase spin-up via Docker.
* Environment file (`.env`) generation and sync.
* Application of database schemas and migrations.
* Secret configuration (App Master Key, Slack details).
* Deno Edge Function deployment.

---

## **Prerequisites 🛠️**

Ensure you have the following installed on your target deployment machine:
* **Node.js** (v18+) and **npm**.
* **Docker** (Required for Option 1: Local Self-Hosted Supabase).
* **Git** (Required for sparse-cloning Supabase).

---

## **Setup 🚀**

Choose the scenario below that matches your deployment target:

### **A. Spin Up a New Local Self-Hosted Supabase Instance (Linux Only)**
Use this option if you want to bootstrap a complete self-hosted instance of Supabase from scratch on your own server.

> [!NOTE]
> If you already have a database instance, skip to **[Section B](#b-deploy-schema-to-an-existing-database-locally-hosted-external-or-supabase-cloud)**.

> [!WARNING]
> **Linux-only.** On macOS/Windows, install manually via [Supabase Docs](https://supabase.com/docs/guides/self-hosting/docker).

#### **Execution Steps:**
1. Run the setup command in your terminal inside the `scripts/` folder:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
   *(Windows/PowerShell users: `./setup.ps1`)*
2. Select **Choice 1** when prompted.
3. Enter the path where the Supabase project files should be cloned (defaults to `~/supabase-project`, which creates [supabase-project](../../supabase-project)).
4. Set your service URLs (e.g. `http://localhost:8000` for Studio/APIs).
5. Enter your connection pooler tenant ID.
6. The script will automatically pull and start all necessary Docker containers, generate passwords/keys, setup JWT secrets, and deploy the LineBuzz database schema/migrations.

> [!NOTE]
> Ensure host port `5432` is free. Stop any local Postgres instance (`sudo systemctl stop postgresql`) or change `POSTGRES_PORT` in [supabase-project/.env](../../supabase-project/.env).

### **B. Deploy Schema to an Existing Database (locally hosted, external, or Supabase Cloud)**
Use this option if you already have a running Supabase instance (such as a Supabase Cloud project, an external self-hosted server, or a local dev database managed via CLI) and just want to deploy the LineBuzz schema.

#### **Cloud Deployment Prerequisites (Supabase Cloud)**
Before running the setup script, you must complete the following steps in your terminal to ensure the setup process can authenticate and deploy your Edge Functions:

1. **Authenticate the Supabase CLI:** Log in to your Supabase account by running the login command in your terminal:
   ```bash
   npx supabase login
   ```
2. **Retrieve your Project Reference:** Obtain your **20-character Project Reference ID** (e.g., `abcd1234efgh5678ijkl`). This is visible in your browser's address bar when looking at your project dashboard: `https://supabase.com/dashboard/project/<project-ref>`.

#### **Execution Steps:**
1. Run the setup command in your terminal inside the `scripts/` folder:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
   *(Windows/PowerShell users: `./setup.ps1`)*
2. Select **Choice 2** when prompted.
3. Enter your database connection URL.
   * *For Supabase Cloud:* Obtain this from your dashboard under **Project Settings > Database > Connection String** (select URI). Ensure you replace the password placeholder with your actual database password.
4. Enter your **Project Reference ID** when prompted to deploy Deno Edge Functions directly to your Cloud project.
5. The script will apply migrations, apply seed data, deploy the Edge Functions via `npx supabase functions deploy`, and setup your configurations.

---

## **Environment Configurations ⚙️**

The deployment settings are configured in [scripts/.env](.env). When running the setup script for the first time, it automatically creates this file from [scripts/.env.example](.env.example).

### **Key Configuration Options**

* **`DEPLOYMENT_TYPE`**: Either `local` (self-hosted Docker) or `cloud` (Supabase Cloud).
* **`DATABASE_URL`**: The database connection string used for migrations.
* **`APP_MASTER_KEY`**: A 32-character hex key used as the root security credential in the database.
  * **What it is used for:** 
    * Encrypting and decrypting Slack integration OAuth tokens.
    * Generating team invite codes.
    * Enforcing workspace validation and member permission policies.
  * **Generation & Storage:** If this key is not defined in `.env` (or is empty in [.env.example](.env.example)), the setup script will **automatically generate** a secure random 32-character hex key for you on the first run and save it to `.env`.
  * > [!WARNING]
    > **Keep this key safe.** Changing it later breaks decryption of existing Slack credentials and invite codes.
* **`MIN_CLIENT_VERSION`**: The minimum supported VS Code extension version (e.g., `0.3.0`). 
  > [!TIP]
  > Leave empty in [.env.example](.env.example) to prompt during setup.
* **`SLACK_*`**: Settings for bi-directional Slack message synchronization.

---

## **Edge Functions & Verification 🕵️**

When using Option 1 (Local Self-Hosted), the script copies your Deno Edge Functions and environment variables directly into the self-hosted Docker volumes. 

To verify that your Edge Function secrets are correctly loaded into the self-hosted runtime, run:
```bash
docker exec supabase-edge-functions env
```

> [!IMPORTANT]
> Local `.env` inside `supabase/functions/` is ignored during deployment. Secrets must be configured in [scripts/.env](.env).
