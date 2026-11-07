# بتا کامل — رله ایران + بکاپ + فایروال (parent executor)

**کنترل:** Shahrah-only (آلمان خروج + اختیاری WaterWall). **مسیر مستقیم آلمان** که الان کار می‌کند حفظ می‌شود؛ رله ایران **اضافه** است.

## توپولوژی

| مسیر | کلاینت به | نیاز |
|------|-----------|------|
| مستقیم (فعلی) | `reality.bluelark.ir` یا IP آلمان | بدون رله |
| رله داخلی | IP ایران :443 | WaterWall دوطرفه + `client-host` |

پورت‌ها (reverse، پیش‌فرض):

| محل | پورت | سرویس |
|-----|------|--------|
| آلمان | 443/tcp | shahrah-xray (REALITY) |
| آلمان | — | WW خروجی به ایران:8443 (خروجی) |
| ایران | 443/tcp | WaterWall کاربر |
| ایران | 8443/tcp | تونل (فقط از IP آلمان) |

WaterWall: `v1.5.2`، SHA256 در `deploy/install.sh` (`WW_SHA256_X64`). باینری از GitHub release؛ بدون Docker.

## فاز A — آلمان (قبلاً انجام شده)

خروج فعال است. برای رله:

```bash
sudo IRAN_PEER_IP=<IRAN_IPV4> ./deploy/beta/germany-attach-waterwall.sh
```

سپس **فقط روی سرور** (نه در گزارش): `scp` فایل `/etc/shahrah/backhaul.key` به ایران.

## فاز B — ایران (رله دائم)

پیش‌نیاز: `backhaul.key` همان آلمان روی `/etc/shahrah/backhaul.key` (0600).

```bash
sudo EXIT_PEER_IP=<GERMANY_IPV4> ./deploy/beta/iran-relay-install.sh
sudo SSH_PORT=22 EXIT_PEER_IP=<GERMANY_IPV4> ./deploy/beta/firewall-iran-relay.sh
```

روی آلمان (لینک اشتراک با IP ایران):

```bash
shahrah --state /etc/shahrah/state.json client-host <IRAN_IPV4>
shahrah --state /etc/shahrah/state.json apply --xray-bin /usr/local/bin/xray \
  --config-out /etc/shahrah/xray.json --group shahrah
systemctl restart shahrah-xray
```

برگشت به مستقیم: `shahrah ... client-host --clear` و apply.

## تعویض سرور خارجی (بدون بازسازی ایران)

1. بکاپ bundle از آلمان قدیم
2. استقرار shahrah روی آلمان جدید از bundle (دستی parent)
3. `germany-attach-waterwall.sh` با همان `IRAN_PEER_IP`
4. روی ایران: `NEW_EXIT_IP=<new> IRAN_SELF_IP=<iran> ./deploy/beta/migrate-exit-public-ip.sh`

کلید REALITY و `backhaul.key` می‌توانند همان بمانند؛ فقط IP همتا در WW عوض می‌شود.

## بکاپ / بازیابی

```bash
sudo ./scripts/backup-shahrah-bundle.sh
sudo ./scripts/restore-shahrah-drill.sh /var/backups/shahrah/shahrah-bundle-....tar.gz.gpg
```

رمز: `/etc/shahrah/backup.pass` (روی همان ماشین، هرگز در آرتیفکت). برای مهاجرت: bundle + pass را با روش امن خودتان منتقل کنید.

زمان‌بندی (cron نمونه، روزانه):

```cron
17 3 * * * root /opt/shahrah/scripts/backup-shahrah-bundle.sh
```

## فایروال آلمان

```bash
sudo SSH_PORT=22 ./deploy/beta/firewall-germany-beta.sh
# در ۱۸۰ ثانیه SSH دوم باز کنید؛ سپس:
touch /var/lib/shahrah/ufw-beta-keep
```

API آمار `10085` روی loopback می‌ماند؛ در UFW باز نمی‌شود.

## پایداری محدود (<=۵ دقیقه)

```bash
sudo DURATION_SEC=300 ./deploy/beta/stability-check.sh
```

## بازگردانی

- آلمان: `deploy/rollback-install.sh` (+ جداگانه `systemctl stop shahrah-waterwall`)
- ایران: `systemctl stop shahrah-waterwall`؛ `ufw --force disable` اگر فعال کردید

## Ubuntu 26.04

در VM agent تست نشد؛ preflight شما 26.04 + Python≥3.11 را تأیید کرد. WaterWall e2e فقط در pytest/lab (بدون باینری زنده در CI).
