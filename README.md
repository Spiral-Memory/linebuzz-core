# **LineBuzz 🧵 Developer Collaboration in VS Code**

## **Overview 📘**

**The backend engine for LineBuzz.** This repository manages the database schema, real-time sync logic, and authentication policies.

## **Core Responsibilities ✨**

* **Data Infrastructure:** PostgreSQL schema and migrations managed via Supabase.
* **Real-time Engine:** Configuration for low-latency broadcast and presence channels.
* **Security (RLS):** Row-Level Security policies to ensure team data remains private.
* **Auth Gateway:** GitHub OAuth configuration and user session management.

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

**3. Initialize Database Secrets & Data:**

Run the following SQL queries in your local Supabase Studio SQL Editor:

_Set the App Master Key_ (generate a key using `openssl rand -hex 16`):

```sql
SELECT vault.create_secret(
  '<YOUR_GENERATED_KEY>',
  'app_master_key_latest',
  'LineBuzz Team Master Key'
);
```

_Set the Seed BIP-39 Words:_

```sql
INSERT INTO internal.bip39_words (id, word)
SELECT 
    ordinality - 1, 
    word
FROM unnest(ARRAY[
    'abandon', 'ability', 'able' /* ... Replace with your list of BIP 39 words ... */
]) WITH ORDINALITY AS t(word, ordinality)
ON CONFLICT (id) DO NOTHING;
```

### **3. Database Migrations**

To apply changes to the local or remote database:

```bash
supabase db push
```

## **Contributing 🤝**

Contributions are always welcome.
Fork the repository, open it in your preferred editor, and use the Supabase CLI to manage migrations.
For significant updates, open an issue first to discuss your approach.