# بعد از رله ایران — hostهای PasarGuard

## مشکل

کاربر باید به **IP ایران :443** وصل شود؛ REALITY همان کلید/SNI خروج است. اگر host در پنل آدرس آلمان دارد، کلاینت مستقیم IP خارج را می‌زند و فیلتر می‌شود.

## راه‌حل (یک خروج)

روی VPS **خروج** (همان state پنل):

```bash
shahrah --state /etc/shahrah/state.json client-host <IP_ایران>
shahrah panel provision --core-name shahrah-nl --prefix nl \
  --panel-url "$SHAHRAH_PANEL_URL" --state /etc/shahrah/state.json
# فقط hostهای جدید؛ اگر host قبلی با آدرس اشتباه است در UI پنل address را به IP ایران عوض کنید
```

`client-host` فقط پورت‌های بحرانی 443/80/53 را در endpoint عوض می‌کند (`state.py`).

## چند خروج (fleet)

روی **مستر** فایل fleet (نمونه: `deploy/fleet.example.json`):

```bash
export SHAHRAH_PANEL_URL=https://panel.example.com:443
export SHAHRAH_PANEL_API_KEY=...
shahrah panel fleet-plan --file /etc/shahrah/fleet.json
shahrah panel fleet-apply --file /etc/shahrah/fleet.json
```

برای مسیر رله، عضو fleet با `client_host` = IP ایران و `host_prefix` جدا (مثلاً `nl-ir`) بسازید.

## brain

`brain_remarks` از خروجی `provision` یا `fleet-plan` را در `/etc/shahrah/brain.json` بگذارید. brain روی **ایران** اجرا می‌شود، API پنل روی **مستر**.

## چک‌لیست

- [ ] ساب کاربر `address` = IP ایران (یا دامنه ورودی ایران)
- [ ] `sni` همان REALITY target (مثلاً cloudflare.com)
- [ ] `inbound_tag` با core خروج یکی است
- [ ] probe user روی همان خروج UUID دارد