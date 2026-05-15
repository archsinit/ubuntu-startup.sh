# Personal Docker Services

This server uses Docker Engine directly with `docker run` scripts.

No Docker Compose.

Services live under:

```text
/opt/services
├── _scripts
├── _env
├── _secrets
├── _volumes
└── README.md
```

## Directory layout

### `/opt/services/_scripts`

Service management scripts.

Recommended naming:

```text
/opt/services/_scripts/myapp_launch.sh
/opt/services/_scripts/myapp_stop.sh
/opt/services/_scripts/myapp_update.sh
/opt/services/_scripts/myapp_logs.sh
```

Each launch script should:

1. decrypt the encrypted env file
2. create a temporary plaintext env file
3. run the container with `--env-file`
4. securely delete the temporary env file on exit

### `/opt/services/_env`

Encrypted service env files.

Use SOPS with age.

Example:

```text
/opt/services/_env/myapp.env.sops
```

Do not store plaintext `.env` files here.

### `/opt/services/_secrets`

Secret files mounted directly into containers.

Use this when an image supports file-based secrets, such as:

```text
POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
```

Example:

```text
/opt/services/_secrets/postgres_password.sops
```

For most small services, encrypted env files are enough.

### `/opt/services/_volumes`

Bind-mounted app data.

Example:

```text
/opt/services/_volumes/myapp
```

Prefer this over anonymous Docker volumes because it makes backup and restore easier.

Back up this directory.

## Docker exposure model

UFW protects the host only.

Docker-published ports are intentional exposure.

Public:

```bash
-p 80:80
-p 443:443
```

Local-only:

```bash
-p 127.0.0.1:8080:8080
```

No host exposure:

```bash
# No -p flag
```

Treat this as public:

```bash
-p 8080:8080
```

That binds to all interfaces by default.

## Install SOPS and age

```bash
sudo apt update
sudo apt install -y age sops
```

Check:

```bash
sops --version
age --version
```

## Create an age key

Run as your admin user:

```bash
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt
chmod 600 ~/.config/sops/age/keys.txt
```

Show the public recipient:

```bash
grep "public key:" ~/.config/sops/age/keys.txt
```

Example output:

```text
# public key: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The `age1...` value is your SOPS recipient.

## Configure SOPS

Create:

```bash
sudo nano /opt/services/.sops.yaml
```

Example:

```yaml
creation_rules:
  - path_regex: _env/.*\.env\.sops$
    age: age1REPLACE_WITH_YOUR_PUBLIC_AGE_RECIPIENT

  - path_regex: _secrets/.*\.sops$
    age: age1REPLACE_WITH_YOUR_PUBLIC_AGE_RECIPIENT
```

Lock it down:

```bash
sudo chown root:docker /opt/services/.sops.yaml
sudo chmod 640 /opt/services/.sops.yaml
```

## Create encrypted env file

Create a plaintext temp file:

```bash
cat > /tmp/myapp.env <<'EOF'
TZ=Pacific/Guam
APP_URL=https://example.com
DATABASE_URL=postgres://myapp:change-me@postgres:5432/myapp
API_KEY=change-me
EOF
```

Encrypt it:

```bash
cd /opt/services
sops --encrypt /tmp/myapp.env > _env/myapp.env.sops
```

Lock it down:

```bash
sudo chown root:docker /opt/services/_env/myapp.env.sops
sudo chmod 640 /opt/services/_env/myapp.env.sops
shred -u /tmp/myapp.env
```

Edit later:

```bash
cd /opt/services
sops _env/myapp.env.sops
```

## Launch script pattern

Create:

```bash
sudo nano /opt/services/_scripts/myapp_launch.sh
```

Template:

```bash
#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

SERVICE_NAME="myapp"
IMAGE="nginx:alpine"

BASE_DIR="/opt/services"
ENV_ENCRYPTED="${BASE_DIR}/_env/${SERVICE_NAME}.env.sops"
VOLUME_DIR="${BASE_DIR}/_volumes/${SERVICE_NAME}"

mkdir -p "${VOLUME_DIR}"

TMP_ENV="$(mktemp "/tmp/${SERVICE_NAME}.env.XXXXXX")"

cleanup() {
  if [[ -f "${TMP_ENV}" ]]; then
    shred -u "${TMP_ENV}" 2>/dev/null || rm -f "${TMP_ENV}"
  fi
}
trap cleanup EXIT

sops --decrypt "${ENV_ENCRYPTED}" > "${TMP_ENV}"
chmod 600 "${TMP_ENV}"

docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || true

docker run -d \
  --name "${SERVICE_NAME}" \
  --restart unless-stopped \
  --env-file "${TMP_ENV}" \
  --network proxy \
  -v "${VOLUME_DIR}:/data" \
  -p 127.0.0.1:8080:80 \
  "${IMAGE}"
```

Make executable:

```bash
sudo chmod 750 /opt/services/_scripts/myapp_launch.sh
sudo chown root:docker /opt/services/_scripts/myapp_launch.sh
```

Run:

```bash
sudo /opt/services/_scripts/myapp_launch.sh
```

## Important secret-handling rules

Never use shell tracing in service scripts:

```bash
set +x
```

Never put secrets directly in `docker run` arguments:

```bash
docker run -e API_KEY=secret-value ...
```

Avoid this because secrets may appear in shell history, process listings, logs, or copied scripts.

Prefer:

```bash
docker run --env-file "${TMP_ENV}" ...
```

The decrypted env file exists only briefly and is removed by the script.

## Stop script

Create:

```bash
sudo nano /opt/services/_scripts/myapp_stop.sh
```

```bash
#!/usr/bin/env bash
set -euo pipefail
set +x

SERVICE_NAME="myapp"

docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || true
```

Permissions:

```bash
sudo chmod 750 /opt/services/_scripts/myapp_stop.sh
sudo chown root:docker /opt/services/_scripts/myapp_stop.sh
```

## Logs script

Create:

```bash
sudo nano /opt/services/_scripts/myapp_logs.sh
```

```bash
#!/usr/bin/env bash
set -euo pipefail
set +x

SERVICE_NAME="myapp"

docker logs -f --tail=200 "${SERVICE_NAME}"
```

Permissions:

```bash
sudo chmod 750 /opt/services/_scripts/myapp_logs.sh
sudo chown root:docker /opt/services/_scripts/myapp_logs.sh
```

## Update script

Create:

```bash
sudo nano /opt/services/_scripts/myapp_update.sh
```

```bash
#!/usr/bin/env bash
set -euo pipefail
set +x

IMAGE="nginx:alpine"

docker pull "${IMAGE}"

/opt/services/_scripts/myapp_launch.sh
```

Permissions:

```bash
sudo chmod 750 /opt/services/_scripts/myapp_update.sh
sudo chown root:docker /opt/services/_scripts/myapp_update.sh
```

## Service lifecycle

Start or recreate:

```bash
sudo /opt/services/_scripts/myapp_launch.sh
```

Stop:

```bash
sudo /opt/services/_scripts/myapp_stop.sh
```

View logs:

```bash
sudo /opt/services/_scripts/myapp_logs.sh
```

Update:

```bash
sudo /opt/services/_scripts/myapp_update.sh
```

Check exposed ports:

```bash
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}"
```

## Recommended container defaults

Use these unless the app needs something different:

```bash
--restart unless-stopped
--network proxy
--env-file "${TMP_ENV}"
```

For local-only admin panels:

```bash
-p 127.0.0.1:8080:8080
```

For public reverse proxy only:

```bash
-p 80:80
-p 443:443
```

For databases:

```bash
# Usually no -p flag
```

Databases should usually be reachable only over Docker networks.

## Example: reverse proxy pattern

One public-facing container:

```bash
-p 80:80
-p 443:443
--network proxy
```

App containers:

```bash
--network proxy
# no public -p
```

This keeps most services private behind the reverse proxy.

## Backups

Back up:

```text
/opt/services/.sops.yaml
/opt/services/_env
/opt/services/_secrets
/opt/services/_volumes
```

Also back up your age private key:

```text
~/.config/sops/age/keys.txt
```

Without the age private key, encrypted env files cannot be decrypted.

Store the age private key somewhere safe, separate from the server.

## Restore checklist

1. Restore `/opt/services`
2. Restore age private key
3. Install Docker, SOPS, and age
4. Recreate Docker network:

```bash
docker network create proxy
```

5. Run service launch scripts:

```bash
sudo /opt/services/_scripts/myapp_launch.sh
```

## Security notes

Docker group membership is root-equivalent.

Anyone who can run Docker commands can effectively control the host.

Keep these files restricted:

```bash
sudo chmod 750 /opt/services
sudo chmod 750 /opt/services/_scripts
sudo chmod 750 /opt/services/_env
sudo chmod 750 /opt/services/_secrets
sudo chmod 750 /opt/services/_volumes
```

Encrypted env files are safe to store, but still restrict access:

```bash
sudo chmod 640 /opt/services/_env/*.sops
```

Never leave decrypted env files on disk.

Launch scripts should always clean up temp env files with a trap.
