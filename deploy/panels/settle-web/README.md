# settle-web — تسویه نمایندگی و فروش مشتری

صورتحساب سقف حجم برای ادمین‌های PasarGuard + صفحهٔ عمومی `/pay/` برای شارژ مشتری.

**کجا:** سرور Exit (کنار پنل PasarGuard)

## نصب سریع (سرور دوست / هر Exit)

روی سرور مقصد با دسترسی root:

```bash
git clone https://github.com/${GITHUB_OWNER}/vpn-infra.git
cd vpn-infra/scripts/settle-web
sudo bash install.sh
```

اسکریپت می‌پرسد: آدرس عمومی پنل، کاربر/رمز settle، listen، و اختیاریاً nginx.

بدون سؤال (اتوماسیون):

```bash
sudo PANEL_BASE='https://panel.example.com:2096' AUTH_USER=settle AUTH_PASS='رمز' \
  PANEL_NGINX_APPLY=y bash install.sh
```

آپدیت بعدی (همان ریپو):

```bash
cd /path/to/vpn-infra && git pull
sudo bash scripts/settle-web/install.sh
# یا اگر قبلاً نصب شده و می‌خواهید همان رمز بماند: فقط Enter روی پرامپت‌ها
```

## پیش‌نیاز

- PasarGuard در Docker روی **همین** سرور (یا `PANEL_API_KEY` + آدرس ریموت در `/root/.vpn-secrets/.env`)
- ترجیحاً `PANEL_API_KEY` در `/root/.vpn-secrets/.env` (برای `/pay/` و شارژ خودکار)
- nginx روی پورت عمومی پنل تا `/settle/` و `/pay/` را پراکسی کند (install پیشنهاد می‌دهد)

## بعد از نصب

| مورد | مسیر |
|------|------|
| سرویس | `systemctl status settle-web` |
| رمز مدیر | `/etc/settle-web/admin.pass` |
| UI تسویه | `https://…/settle/` |
| فروش مشتری | `https://…/pay/` |
| برند /pay/ | settle → **تنظیمات** (ادمین ۱ / مدیر): نوار بالا، شعار، خوش‌آمد، تلفن، تلگرام |

## برند صفحهٔ `/pay/`

- قبل از ورود: ظاهر دکور (نوار بالا + کاتالوگ + شعار ورود)
- بعد از ورود: نوار بالا و کاتالوگ مخفی؛ متن خوش‌آمد بالای فرم پلن‌ها
- ویرایش فقط با حساب مدیر settle (اپراتور / ادمین ۱)

## عیب‌یابی کوتاه

```bash
systemctl status settle-web
journalctl -u settle-web -n 80 --no-pager
curl -sS http://127.0.0.1:8789/pay/api/brand
```
