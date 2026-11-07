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

---

## ارتقا / بازپیکربندی روی state موجود (PR بتا — نه `main`)

روی خروج تست **185.19.33.221** اگر `state.json` از قبل هست و فقط `--host` / `--target` / `--multi-port` می‌دهید، دیگر نادیده گرفته نمی‌شود:

```bash
sudo ./deploy/install.sh \
  --host 185.19.33.221 \
  --target www.cloudflare.com
```

برای شکستن خط در shell حتماً `\` آخر خط باشد؛ وگرنه `--target: command not found` خطای **shell** است نه شاهراه.

`--multi-port` فقط وقتی صریحاً بزنید listener **53** اضافه می‌کند (ممکن است stub `systemd-resolved` غیرفعال شود؛ DNS سیستم را قبلش بدانید).

آرتیفکت این PR را از Actions/بستهٔ `package-beta-release.sh` بگیرید؛ **`origin/main` هنوز این رفتار را ندارد.**

## چند خروج هم‌زمان از یک ایران (de + tr)

هر **نام** = یک WaterWall جدا + پورت کاربر روی ایران + کلید backhaul خودش. کلاینت روی **همان exit** لینک می‌گیرد:

```bash
# ایران
sudo shahrah relay peer-add --name de --exit-ip <EXIT1_IPV4> --user-port 443 \
  --tunnel-port 8443 --iran-ip <IRAN_IPV4> --entry-host <IRAN_IPV4>
sudo shahrah relay print-unit > /etc/systemd/system/shahrah-waterwall@.service
sudo systemctl daemon-reload
sudo systemctl enable --now shahrah-waterwall@de

# دوم (مثال ترکیه — IP را خودتان بگذارید، نه مقدار ساختگی در ریپو)
sudo shahrah relay peer-add --name tr --exit-ip <EXIT2_IPV4> --user-port 4430 \
  --tunnel-port 9453 --iran-ip <IRAN_IPV4> --entry-host <IRAN_IPV4>
sudo systemctl enable --now shahrah-waterwall@tr
```

روی **exit1**:

```bash
shahrah link USER --entry-host <IRAN_IPV4> --entry-port 443
```

روی **exit2**:

```bash
shahrah link USER --entry-host <IRAN_IPV4> --entry-port 4430
```

**PasarGuard:** هویت کاربر روی هر exit جدا است؛ sync خودکار UUID بین exitها وعده داده نشده است.

## ویزارد ترمینال و حذف امن

```bash
sudo ./deploy/shahrah-wizard.sh          # فقط TTY تعاملی
NO_COLOR=1 sudo ./deploy/install.sh ... # بدون رنگ
sudo ./deploy/uninstall-shahrah.sh --dry-run
sudo ./deploy/uninstall-shahrah.sh --purge --backup /root/shahrah-backups --yes
```

`uninstall` هرگز SSH یا ufw سراسری را reset نمی‌کند.

## نصب از clone تازه / ارتقا روی main (بعد از merge والد)

```bash
git clone https://github.com/rootitdev/shahrah.git /opt/shahrah
cd /opt/shahrah && git checkout main
sudo ./deploy/install.sh --host 185.19.33.221 --target www.cloudflare.com
```

**checkout جدا در `/opt/shahrah` با تغییر محلی:**

```bash
sudo ./deploy/upgrade-shahrah.sh --ref main
# فقط با فلگ صریح host/target/multi-port عوض می‌شود؛ credential در /etc/shahrah می‌ماند
```

**چند خروج (bootstrap هر طرف):**

```bash
# ایران
sudo PEER_NAME=de EXIT_IP=<EXIT1_IPV4> IRAN_IP=<IRAN_IPV4> ENTRY_HOST=<IRAN_IPV4> \
  ./deploy/beta/iran-bootstrap-relay-peer.sh
# سپس دستورات peer-activate (ufw + systemctl)

# exit1
sudo scp /etc/shahrah/backhaul-de.key root@<EXIT1>:/etc/shahrah/backhaul-de.key
sudo PEER_NAME=de IRAN_PEER_IP=<IRAN_IPV4> ./deploy/beta/exit-attach-relay-peer.sh
```

PasarGuard روی سرور اصلی **الان** نصب/یکپارچه نیست — مدیریت کاربر هر exit جدا است.
