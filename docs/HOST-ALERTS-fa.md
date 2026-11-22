# آلرت تلگرام + Swap روی سرورها

هر VPS هر **۲ دقیقه** RAM، load و سرویس‌های مهم را چک می‌کند. فقط وقتی **وضعیت عوض شود** (یا بحران تکرار شود) پیام می‌فرستد.

## نصب

```bash
cd /opt/shahrah   # یا مسیر ریپو
sudo ./deploy/install-host-alert.sh
sudo cp deploy/examples/host-alert-DE.env /etc/shahrah/host-alert.env   # نقش درست
sudo systemctl start shahrah-host-alert.service   # تست دستی
```

## متغیرهای لازم در `/root/.vpn-secrets/.env`

| متغیر | توضیح |
|--------|--------|
| `TELEGRAM_BOT_TOKEN` | از [@BotFather](https://t.me/BotFather) — مثلاً `7123456789:AAH...` |
| `TELEGRAM_CHAT_ID` | عدد chat (گروه یا خودت) — مثلاً `-1001234567890` یا `123456789` |

می‌توانی همان ربات settle را استفاده کنی یا ربات جدا برای آلرت زیرساخت.

### گرفتن `CHAT_ID`

1. به ربات پیام بده (یا ربات را به گروه ادمین کن و یک پیام بفرست).
2. در مرورگر: `https://api.telegram.org/bot<TOKEN>/getUpdates` — فیلد `chat.id`.

## فایل نقش: `/etc/shahrah/host-alert.env`

نمونه‌ها: `deploy/examples/host-alert-{de,nl,ir}.env`

- `SERVICES` — یونیت‌های systemd
- `DOCKER_NAMES` — کانتینر لازم (مثلاً PasarGuard روی مستر)
- `CHECK_PORT_8000=1` — فقط مستر

## دستورات

```bash
systemctl status shahrah-host-alert.timer
journalctl -u shahrah-host-alert.service -n 20
/usr/local/sbin/shahrah-swap.sh
```