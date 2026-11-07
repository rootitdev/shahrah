# بتا شاهراه — آلمان اول، ایران بعد

**صفحهٔ کنترل:** فقط **Shahrah brain** (`shahrah-brain.service`). کیت `vpn_failover` روی همان خروج **ممنوع** (`enforce_control_plane` در `deploy/install.sh`).

## توپولوژی بتا (دو سرور خریداری‌شده)

| فاز | میزبان | نقش | RAM پذیرفته‌شده |
|-----|--------|-----|----------------|
| ۱ | آلمان | خروج REALITY + Xray + brain (پس از پنل) | ~1GB — بدون HY2/WARP/paqet |
| ۲ | ایران | فقط در صورت نیاز: `--role relay` / WaterWall | ~2GB — **نه** کیت کامل فاز ۱ |

`bluelark.ir`: برای REALITY زیردامنه **DNS-only** (بدون پروکسی نارنجی). CDN/XHTTP را در بتا خاموش بگذارید.

## نصب فاز ۱ (اجرای توسط parent)

```bash
cd shahrah-RELEASE-*/
sudo REALITY_HOST=reality.bluelark.ir ./deploy/beta/germany-exit-install.sh
```

پس از نصب:

```bash
shahrah --state /etc/shahrah/state.json user add beta1
shahrah --state /etc/shahrah/state.json apply --xray-bin /usr/local/bin/xray \
  --config-out /etc/shahrah/xray.json --group shahrah
systemctl restart shahrah-xray
shahrah --state /etc/shahrah/state.json link beta1   # خروجی را فقط روی سرور ببینید
```

## پورت‌ها و فایروال

| سرویس | پورت | یادداشت |
|--------|------|---------|
| SSH | 22 | دست‌نخورده؛ ufw در بتا `--no-firewall` |
| REALITY | 443/tcp | تنها inbound اصلی |
| stats API | 127.0.0.1:10085 | loopback |
| brain / sub | 127.0.0.1 | پس از پیکربندی پنل |

## تأیید (روی سرور)

```bash
systemctl is-active shahrah-xray
/usr/local/bin/xray run -test -c /etc/shahrah/xray.json
bash -n deploy/install.sh deploy/rollback-install.sh
```

## rollback

```bash
sudo ./deploy/rollback-install.sh          # برگرداندن nginx/caddy از snapshot
sudo ./deploy/rollback-install.sh --purge-config   # حذف /etc/shahrah
```

## پنل‌های فروش

در بتا **نصب نکنید**: `settle-web`, `ig-mult` (root + سطح حمله). در صورت نیاز فقط `PANELS=` خالی.

## ایران — مسدودکننده‌های باقی

نصب کامل `vpn-infra-kit` روی 1–2GB بدون اندازه‌گیری **توصیه نمی‌شود**. فاز ۲ فقط اگر از شبکه کاربر به آلمان نمی‌رسید: `install.sh --role relay` با اسکریپت جدا (آرتیفکت Iran blockers در MANIFEST).

See English: `deploy/beta/README.md`
