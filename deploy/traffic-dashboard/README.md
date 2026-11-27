# پنل مصرف و هزینهٔ شاهراه

آدرس پنل https://traffic.argosatra.ir است. مسیر تنظیمات /settings است. قبض، فروش روزانه، نام سرور، تعرفه و مصرف تاریخی از همین بخش ثبت می‌شوند. تاریخ گزارش شمسی است. مبلغ فروش و حجم فروخته‌شده را مستقل از مصرف شبکه وارد کنید. مبلغ قبض در تاریخ ثبت با برآورد بازه مقایسه می‌شود. برای دوره‌های متفاوت، اختلاف لزوماً خطای تعرفه نیست.

نمونه‌گیری روی رابط عمومی در ساعت ۰۰ و ۱۲ و ارسال دسته‌ای در ساعت ۰۶ تهران انجام می‌شود. اولین شمارنده فقط مبناست. صف هر سرور تا رسیدن تأیید مستر نگه داشته می‌شود. جزئیات روزانه تاریخ‌های ناقص و برآوردی را نشان می‌دهد.

## نگهداری

برای تغییر نام رابط، INTERFACE در /etc/shahrah-traffic/agent.env را به‌روزرسانی کنید. اجرای بعدی تایمر آن را می‌خواند. زمان‌بندی و تحویل را با systemctl list-timers و journalctl -u shahrah-traffic-deliver بررسی کنید.

تعویض رمز همهٔ نشست‌ها را باطل می‌کند. دستور را روی مستر اجرا کنید:

    sudo -u shahrah-traffic python3 /opt/shahrah-traffic/manage.py --db /var/lib/shahrah-traffic/dashboard.db password --name admin

بکاپ آنلاین و بازیابی به مسیر جدید:

    sudo python3 /opt/shahrah-traffic/manage.py --db /var/lib/shahrah-traffic/dashboard.db backup /root/dashboard-backup.sqlite
    sudo python3 /opt/shahrah-traffic/manage.py --db /root/dashboard-restored.sqlite restore /root/dashboard-backup.sqlite

نسخهٔ بازیابی را ابتدا جداگانه بررسی کنید. برای بازگردانی سرویس، پنل را متوقف کنید، پوشهٔ فعلی دیتابیس و فایل‌های جانبی SQLite را نگه دارید و نسخهٔ بازیابی‌شده را با مالکیت کاربر shahrah-traffic و سطح دسترسی قبلی جایگزین کنید. کلیدهای عامل‌ها جداگانه در /etc/shahrah-traffic/token نگهداری می‌شوند.

برای بازگشت از استقرار، نسخهٔ قبلی Caddyfile را اعتبارسنجی و بازیابی کنید و Caddy را reload کنید. سرویس جدید مستر و دو تایمر جدید هر چهار سرور را متوقف و غیرفعال کنید. دیتا و صف‌ها باقی می‌مانند.
