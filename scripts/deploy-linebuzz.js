const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const { Client } = require('pg');

require('dotenv').config({ path: path.resolve(__dirname, './.env') });

function askQuestion(query) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    return new Promise(resolve => rl.question(query, ans => {
        rl.close();
        resolve(ans);
    }));
}

function updateEnvFile(key, value) {
    const envPath = path.resolve(__dirname, './.env');
    let content = '';
    if (fs.existsSync(envPath)) {
        content = fs.readFileSync(envPath, 'utf8');
    }
    const regex = new RegExp(`^${key}=.*`, 'm');
    if (regex.test(content)) {
        content = content.replace(regex, `${key}=${value}`);
    } else {
        content += `\n${key}=${value}`;
    }
    fs.writeFileSync(envPath, content.trim() + '\n', 'utf8');
}

async function getOrPrompt(key, promptMsg, defaultValue = '') {
    if (process.env[key]) {
        return process.env[key];
    }
    if (process.env.NON_INTERACTIVE) {
        return defaultValue;
    }
    const ans = await askQuestion(`${promptMsg} [${defaultValue}]: `);
    const result = ans.trim() || defaultValue;
    updateEnvFile(key, result);
    return result;
}

function getEdgeSecrets() {
    const keys = [
        'SLACK_CLIENT_ID',
        'SLACK_CLIENT_SECRET',
        'SLACK_SIGNING_SECRET',
        'X_WEBHOOK_SECRET',
        'LINEBUZZ_PAGE_URL'
    ];
    const secrets = {};
    keys.forEach(k => {
        if (process.env[k]) {
            secrets[k] = process.env[k];
        }
    });
    return secrets;
}

function deployEdgeFunctions(deployType, projectDir, projectRef) {
    const edgeSecrets = getEdgeSecrets();
    if (deployType === 'local' && projectDir) {
        console.log('Deploying Edge Functions to self-hosted volume...');
        const targetDir = path.join(projectDir, 'volumes/functions');
        const sourceDir = path.resolve(__dirname, '../supabase/functions');
        if (fs.existsSync(sourceDir)) {
            fs.mkdirSync(targetDir, { recursive: true });
            fs.cpSync(sourceDir, targetDir, {
                recursive: true,
                filter: (src) => path.basename(src) !== '.env'
            });
        }
        const functionsEnvPath = path.join(targetDir, '.env');
        let content = '';
        if (fs.existsSync(functionsEnvPath)) {
            content = fs.readFileSync(functionsEnvPath, 'utf8');
        }
        Object.entries(edgeSecrets).forEach(([key, val]) => {
            const regex = new RegExp(`^${key}=.*`, 'm');
            if (regex.test(content)) {
                content = content.replace(regex, `${key}=${val}`);
            } else {
                content += `\n${key}=${val}`;
            }
        });
        fs.writeFileSync(functionsEnvPath, content.trim() + '\n', 'utf8');
        console.log('Edge secrets synced to self-hosted volume environment.');

        const composePath = path.join(projectDir, 'docker-compose.yml');
        if (fs.existsSync(composePath)) {
            let composeContent = fs.readFileSync(composePath, 'utf8');
            const functionsRegex = /^(  functions:\s*\n)/m;
            if (functionsRegex.test(composeContent) && !composeContent.includes('./volumes/functions/.env')) {
                composeContent = composeContent.replace(functionsRegex, '$1    env_file:\n      - ./volumes/functions/.env\n');
                fs.writeFileSync(composePath, composeContent, 'utf8');
                console.log('Automatically configured env_file for functions service in docker-compose.yml');
            }
        }
        try {
            const { execSync } = require('child_process');
            console.log('Restarting functions service to apply secrets...');
            execSync('docker compose up -d --force-recreate --no-deps functions', { cwd: projectDir, stdio: 'inherit' });
        } catch (e) {
            console.error('Failed to restart functions service:', e.message);
        }
    } else if (deployType === 'cloud' && projectRef) {
        console.log(`Deploying Edge Functions to Supabase Cloud (Project Ref: ${projectRef})...`);
        try {
            const { execSync } = require('child_process');
            if (Object.keys(edgeSecrets).length > 0) {
                console.log('Syncing Edge Function secrets to Supabase Cloud...');
                const tempEnvPath = path.resolve(__dirname, './.env.temp');
                const envContent = Object.entries(edgeSecrets).map(([k, v]) => `${k}=${v}`).join('\n');
                fs.writeFileSync(tempEnvPath, envContent + '\n', 'utf8');
                execSync(`npx supabase secrets set --project-ref ${projectRef} --env-file "${tempEnvPath}"`, { stdio: 'inherit' });
                fs.unlinkSync(tempEnvPath);
            }
            execSync(`npx supabase functions deploy --project-ref ${projectRef}`, { stdio: 'inherit' });
            console.log('Edge Functions deployed successfully to Supabase Cloud.');
        } catch (e) {
            console.error('Failed to deploy Edge Functions to Supabase Cloud:', e.message);
            console.log('Make sure you are logged in to Supabase CLI (run: npx supabase login).');
        }
    }
}

async function runMigrations(client) {
    await client.query(`
        CREATE SCHEMA IF NOT EXISTS supabase_migrations;
        CREATE TABLE IF NOT EXISTS supabase_migrations.schema_migrations (
            version text NOT NULL PRIMARY KEY
        );
    `);

    const migrationsDir = path.resolve(__dirname, '../supabase/migrations');
    if (!fs.existsSync(migrationsDir)) {
        return;
    }
    const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();

    for (const file of files) {
        const version = file.split('_')[0];
        const check = await client.query('SELECT 1 FROM supabase_migrations.schema_migrations WHERE version = $1', [version]);
        if (check.rowCount === 0) {
            console.log(`Applying migration: ${file}`);
            const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
            await client.query('BEGIN');
            try {
                await client.query(sql);
                await client.query('INSERT INTO supabase_migrations.schema_migrations (version) VALUES ($1)', [version]);
                await client.query('COMMIT');
            } catch (err) {
                await client.query('ROLLBACK');
                throw err;
            }
        }
    }
}

async function applySeed(client) {
    console.log('Applying seed data...');
    const seedSql = fs.readFileSync(path.resolve(__dirname, '../supabase/seed.sql'), 'utf8');
    await client.query(seedSql);
}

async function applyConfig(client, masterKey, minVersion, configureSlack, slackBaseUrl, slackWebhookSecret, slackNotifyUrl) {
    console.log('Applying configuration settings...');

    let masterKeySql = fs.readFileSync(path.resolve(__dirname, '../supabase/snippets/set_master_key.sql'), 'utf8');
    masterKeySql = masterKeySql.replace('<YOUR_MASTER_KEY>', masterKey);
    await client.query(masterKeySql);

    let versionSql = fs.readFileSync(path.resolve(__dirname, '../supabase/snippets/set_min_client_version.sql'), 'utf8');
    versionSql = versionSql.replace('<MIN_SUPPORTED_CLIENT_VERSION>', minVersion);
    await client.query(versionSql);

    if (configureSlack) {
        console.log('Applying Slack integration settings...');
        let slackUrlSql = fs.readFileSync(path.resolve(__dirname, '../supabase/snippets/set_slack_oauth_url.sql'), 'utf8');
        slackUrlSql = slackUrlSql.replace('<YOUR_SLACK_OAUTH_URL>', slackBaseUrl);
        await client.query(slackUrlSql);

        let slackNotifySql = fs.readFileSync(path.resolve(__dirname, '../supabase/snippets/set_slack_notify_trigger.sql'), 'utf8');
        slackNotifySql = slackNotifySql
            .replace('<YOUR-SLACK-WEBHOOK-SECRET>', slackWebhookSecret)
            .replace('<YOUR-SLACK-NOTIFY-EDGE-FUNCTION-URL>', slackNotifyUrl);
        await client.query(slackNotifySql);
    }
}

async function main() {
    let deployType = process.env.DEPLOYMENT_TYPE;
    if (!deployType) {
        if (process.env.SUPABASE_PROJECT_DIR) {
            deployType = 'local';
        } else if (process.env.SUPABASE_PROJECT_REF) {
            deployType = 'cloud';
        } else {
            deployType = await getOrPrompt('DEPLOYMENT_TYPE', 'Select Deployment Type (local/cloud)', 'local');
            deployType = deployType.toLowerCase() === 'cloud' ? 'cloud' : 'local';
        }
    }

    let projectDir = '';
    let projectRef = '';

    if (deployType === 'local') {
        projectDir = await getOrPrompt('SUPABASE_PROJECT_DIR', 'Enter path to self-hosted Supabase directory (leave empty to skip function deployment)', '');
    } else if (deployType === 'cloud') {
        projectRef = await getOrPrompt('SUPABASE_PROJECT_REF', 'Enter Supabase Project Ref (leave empty to skip function deployment)', '');
    }

    const dbUrl = await getOrPrompt('DATABASE_URL', 'Enter Database Connection URL', 'postgresql://postgres:postgres@localhost:54322/postgres');

    let masterKey = process.env.APP_MASTER_KEY;
    if (!masterKey) {
        masterKey = crypto.randomBytes(16).toString('hex');
        console.log(`Generated team master key: ${masterKey}`);
        updateEnvFile('APP_MASTER_KEY', masterKey);
    }

    const minVersion = await getOrPrompt('MIN_CLIENT_VERSION', 'Enter Min Client Version', '0.3.0');

    const client = new Client({ connectionString: dbUrl });
    await client.connect();

    try {
        deployEdgeFunctions(deployType, projectDir, projectRef);
        await runMigrations(client);
        await applySeed(client);

        let configureSlack = false;
        let slackBaseUrl = process.env.SLACK_BASE_URL;
        let slackWebhookSecret = process.env.SLACK_WEBHOOK_SECRET;
        let slackNotifyUrl = process.env.SLACK_NOTIFY_URL;

        if (slackBaseUrl || slackWebhookSecret || slackNotifyUrl) {
            configureSlack = true;
        } else if (!process.env.NON_INTERACTIVE) {
            const slackAns = await askQuestion('Configure Slack integration? (y/n) [n]: ');
            if (slackAns.trim().toLowerCase() === 'y') {
                configureSlack = true;
                slackBaseUrl = await getOrPrompt('SLACK_BASE_URL', 'Slack Base URL');
                slackWebhookSecret = await getOrPrompt('SLACK_WEBHOOK_SECRET', 'Slack Webhook Secret');
                slackNotifyUrl = await getOrPrompt('SLACK_NOTIFY_URL', 'Slack Notify URL');
            }
        }

        await applyConfig(client, masterKey, minVersion, configureSlack, slackBaseUrl, slackWebhookSecret, slackNotifyUrl);
        console.log('Deploy completed successfully.');
        if (deployType === 'local') {
            console.log('\nNOTE: To verify that your Edge Function secrets are loaded, run:');
            console.log('docker exec supabase-edge-functions env\n');
        }
    } catch (err) {
        console.error('Deployment failed:', err);
        process.exitCode = 1;
    } finally {
        await client.end();
    }
}

main();
