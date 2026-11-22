# Backup (Shahrah native)

| Script | Role |
|--------|------|
| `scripts/backup-shahrah-bundle.sh` | Quick encrypted `/etc/shahrah` on one node |
| `scripts/backup-stack.sh` | Full stack: master DB + panels + optional SSH peers |
| `scripts/backup-vpn.sh` | Alias → `backup-stack.sh` |
| `scripts/restore-shahrah-drill.sh` | Restore drill for bundle |

## Passphrase

Either `/etc/shahrah/backup.pass` (auto-created) or in `/root/.vpn-secrets/.env`:

```bash
BACKUP_PASSPHRASE='...'
```

Never commit this file.

## Master (panel + panels)

```bash
# Optional: pull Iran / exit configs over SSH (key auth)
export BACKUP_IRAN_HOST=root@IRAN_IP
export BACKUP_EXIT_HOST=root@EXIT_IP
sudo ./scripts/backup-stack.sh
```

Output: `/var/backups/shahrah/shahrah-stack-*.tar.gz.gpg` (default `RETAIN=14` days).

Cron example:

```cron
17 3 * * * root /opt/shahrah/scripts/backup-stack.sh >>/var/log/shahrah-backup.log 2>&1
```

## Single node

```bash
sudo ./scripts/backup-shahrah-bundle.sh
```

## Cloudflare DNS

Token `CF_API_TOKEN` (DNS:Edit) in secrets env:

```bash
shahrah cf-dns zones
shahrah cf-dns list ZONE_ID
shahrah cf-dns upsert reality.example.com 203.0.113.1 false ZONE_ID
```

REALITY exit records should stay **DNS-only (grey)**; CDN orange only for crisis XHTTP hosts — see [CDN.md](CDN.md).