#!/bin/bash
set -e

for cmd in node npm; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: $cmd is required but not installed."
        exit 1
    fi
done

if [ ! -d "node_modules" ] || [ ! -d "node_modules/pg" ] || [ ! -d "node_modules/dotenv" ]; then
    echo "Installing database dependencies..."
    npm install
fi

echo "Welcome to LineBuzz Core Setup Suite!"
echo "Select Setup Option:"
echo "1) Setup local self-hosted Supabase and deploy schema"
echo "2) Deploy schema to an existing database (local dev, self-hosted, or cloud)"
read -r -p "Choice: " choice

if [ "$choice" = "1" ]; then
    bash ./setup-supabase.sh
    node ./deploy-linebuzz.js
elif [ "$choice" = "2" ]; then
    node ./deploy-linebuzz.js
else
    echo "Invalid choice."
    exit 1
fi
