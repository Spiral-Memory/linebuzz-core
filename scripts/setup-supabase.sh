#!/bin/bash
set -e

if [ "$(uname)" != "Linux" ]; then
    echo "Linux OS is required to run this script."
    echo "Refer to: https://supabase.com/docs/guides/self-hosting for installing Supabase on other operating systems"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"
PARENT_DIR="$(dirname "$ROOT_DIR")"

read -r -p "Enter path to install Supabase project [$PARENT_DIR/supabase-project]: " SUPABASE_DIR_INPUT
SUPABASE_DIR_INPUT=${SUPABASE_DIR_INPUT:-"$PARENT_DIR/supabase-project"}

if [[ "$SUPABASE_DIR_INPUT" == /* ]]; then
    SUPABASE_DIR_NAME="$(basename "$SUPABASE_DIR_INPUT")"
    SUPABASE_TARGET_PARENT="$(dirname "$SUPABASE_DIR_INPUT")"
else
    SUPABASE_DIR_NAME="$(basename "$SUPABASE_DIR_INPUT")"
    SUPABASE_TARGET_PARENT="$(dirname "$PARENT_DIR/$SUPABASE_DIR_INPUT")"
fi

SUPABASE_DIR="$SUPABASE_TARGET_PARENT/$SUPABASE_DIR_NAME"

if [ -d "$SUPABASE_DIR" ]; then
    if [ ! -f "$SUPABASE_DIR/run.sh" ]; then
        echo "Error: $SUPABASE_DIR directory exists but run.sh was not found."
        echo "Please delete the existing directory using: rm -rf \"$SUPABASE_DIR\""
        echo "And then re-run this script."
        exit 1
    fi
else
    cd "$SUPABASE_TARGET_PARENT"
    curl -fsSL https://supabase.link/setup.sh | sh -s -- --project-dir "$SUPABASE_DIR_NAME"
    if [ ! -d "$SUPABASE_DIR" ]; then
        echo "Failed to create $SUPABASE_DIR."
        exit 1
    fi
fi

cd "$SUPABASE_DIR"

DEFAULT_TENANT=$(grep '^POOLER_TENANT_ID=' .env | cut -d'=' -f2- | tr -d '\r')
DEFAULT_TENANT=${DEFAULT_TENANT:-"your-tenant-id"}

read -r -p "Enter connection pooler tenant ID [$DEFAULT_TENANT]: " TENANT_INPUT
TENANT_ID=${TENANT_INPUT:-"$DEFAULT_TENANT"}

if grep -q "^POOLER_TENANT_ID=" .env; then
    sed -i "s|^POOLER_TENANT_ID=.*|POOLER_TENANT_ID=${TENANT_ID}|" .env
else
    echo "POOLER_TENANT_ID=${TENANT_ID}" >> .env
fi



bash run.sh start

POSTGRES_PASS=$(grep '^POSTGRES_PASSWORD=' .env | cut -d'=' -f2- | tr -d '\r')
DB_URL="postgresql://postgres.${TENANT_ID}:${POSTGRES_PASS}@localhost:5432/postgres"

cd "$SCRIPT_DIR"
if [ ! -f ".env" ]; then
    cp .env.example .env
fi

if grep -q "^DATABASE_URL=" .env; then
    sed -i "s|^DATABASE_URL=.*|DATABASE_URL=${DB_URL}|" .env
else
    echo "DATABASE_URL=${DB_URL}" >> .env
fi

if grep -q "^SUPABASE_PROJECT_DIR=" .env; then
    sed -i "s|^SUPABASE_PROJECT_DIR=.*|SUPABASE_PROJECT_DIR=${SUPABASE_DIR}|" .env
else
    echo "SUPABASE_PROJECT_DIR=${SUPABASE_DIR}" >> .env
fi

echo "Supabase self-hosted instance started successfully."
echo "Connection string updated in .env."
echo ""
echo "--------------------------------------------------------"
echo "Supabase Self-Hosted Info:"
echo "- Saved path: $SUPABASE_DIR"
echo "- Studio credentials: Find DASHBOARD_USERNAME and DASHBOARD_PASSWORD in $SUPABASE_DIR/.env"
echo "- View API keys / secrets: Run 'sh run.sh secrets' inside the project folder"
echo "- How to remove: Run './reset.sh' inside the project folder, then run 'rm -rf \"$SUPABASE_DIR\"'"
echo "--------------------------------------------------------"
