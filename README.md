# شاهراه (Shahrah)

پلتفرم ضدسانسور روی [Xray-core](https://github.com/XTLS/Xray-core) برای دسترسی پایدار به شبکه‌های اجتماعی، پیام‌رسان و سرویس‌های AI.

شاهراه **فقط نصب‌کنندهٔ WaterWall نیست.** هستهٔ کار Xray + REALITY است؛ تانل ایران↔خارج، پنل، و مسیرهای بحرانی **اختیاری** و جدا نصب می‌شوند.

---

## دو حالت نصب (مهم)

### حالت ۱ — فقط سرور خارج (Exit)

یک VPS خارج داری. کلاینت **مستقیم** به همان سرور وصل می‌شود.  
سرور ایران / تانل لازم نیست.

مناسب وقتی: تست، تعداد کم کاربر، یا هنوز رله ایران نخواستی.  
محدودیت: از بعضی شبکه‌های داخل ایران، IP خارج ممکن است مستقیم فیلتر شود.

```bash
ssh root@IP_خارج
cd /opt && git clone https://github.com/rootitdev/shahrah.git && cd shahrah

./deploy/install.sh \
  --host IP_خارج \
  --target www.cloudflare.com \
  --multi-port
```

- `--host` = آدرس همین سرور خارج (IP یا دامنه)
- `--target` = فقط **پوشش TLS** (لباس ترافیک)؛ کلاینت به Cloudflare وصل نمی‌شود
- `--multi-port` = علاوه بر 443، پورت بحرانی 53 هم باز می‌شود

---

### حالت ۲ — ایران + خارج (رله بین کاربر و Exit)

دو VPS: **ایران** و **خارج**.  
کاربر → ایران → تانل → خارج → اینترنت آزاد.

اینجا WaterWall (و در صورت نیاز paqet / مسیرهای دیگر) برای **بک‌هال بین دو سرور** است، نه جایگزین کل پروژه.

**الف) خارج**

```bash
ssh root@IP_خارج
cd /opt && git clone https://github.com/rootitdev/shahrah.git && cd shahrah

./deploy/install.sh \
  --host IP_خارج \
  --target www.cloudflare.com \
  --multi-port \
  --with-waterwall exit \
  --ww-peer IP_ایران
```

کلید تانل را از Exit بردار (معمولاً زیر `/etc/shahrah/`) و به ایران کپی کن.

**ب) ایران — رله**

```bash
ssh root@IP_ایران
cd /opt && git clone https://github.com/rootitdev/shahrah.git && cd shahrah

./deploy/install.sh \
  --role relay \
  --with-waterwall iran \
  --ww-peer IP_خارج
```

**ج) ایران — brain (سلامت مسیر + هدایت پنل)**

```bash
./deploy/install.sh --role brain
```

**د) پنل کاربران (PasarGuard)** جدا نصب می‌شود؛ بعد با API به شاهراه وصل می‌شود.  
جزئیات: [docs/PANEL.md](docs/PANEL.md)

> نصب را روی **خود VPS** بزن (با SSH). روی لپ‌تاپ / WSL نصب نکن.

---

## شاهراه از چه چیزهایی تشکیل شده؟

| لایه | نقش | اجباری؟ |
|---|---|---|
| Xray + REALITY (Vision / XHTTP) | تونل اصلی کاربر | بله (Exit) |
| Brain + Oracle | سنجش مسیر سالم و مرتب‌سازی host در پنل | برای حالت پایدار پیشنهاد می‌شود |
| PasarGuard | کاربر، حجم، سابسکریپشن | برای فروش/مدیریت کاربر |
| WaterWall | بک‌هال ایران↔خارج | فقط حالت ۲ |
| paqet / Hysteria2 / WARP / CDN-XHTTP | مسیرهای کمکی / بحران | اختیاری |
| rootit + پنل‌های `/ig/` `/settle/` `/watch/` | بازیابی ساب، فروش، دیده‌بان | اختیاری |

ایده این است بهترین قطعات چند پروژه (Xray/REALITY، پنل PasarGuard، بک‌هال، health، ops) کنار هم باشند؛ WaterWall فقط **یک** گزینه برای لینک دو سرور است.

---

## بعد از نصب Exit — کار روزمره

```bash
shahrah user add alice
shahrah apply --xray-bin /usr/local/bin/xray \
  --config-out /etc/shahrah/xray.json --group shahrah
systemctl restart shahrah-xray

shahrah link alice   # لینک vless://
shahrah sub alice    # بدنهٔ ساب
```

کلاینت‌های آماده (v2rayNG، Hiddify، Streisand، …) لینک را ایمپورت می‌کنند.

---

## اسناد بیشتر

| سند | موضوع |
|---|---|
| [docs/OPERATOR.md](docs/OPERATOR.md) | Runbook اپراتور |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | معماری |
| [docs/PANEL.md](docs/PANEL.md) | اتصال به PasarGuard |
| [docs/PANELS.md](docs/PANELS.md) | پنل‌های اختیاری ig / settle / watch |
| [docs/CDN.md](docs/CDN.md) | لبه CDN |
| [docs/CAPACITY.md](docs/CAPACITY.md) | ظرفیت |

وضعیت آزمایشگاهی و محدودیت‌ها: [docs/EVIDENCE.md](docs/EVIDENCE.md)

---

## توسعه

Python 3.11+، بدون وابستگی runtime:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest
```

## مجوز

Apache-2.0 — [LICENSE](LICENSE).  
PasarGuard (AGPL-3.0) فقط از طریق REST API استفاده می‌شود و داخل این ریپو bundle نشده است.
