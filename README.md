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

```bash
git clone https://github.com/Spiral-Memory/linebuzz-core.git
cd linebuzz-core

supabase start
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