"""Persian management views for measured traffic and estimated charges."""
import html
import time
from datetime import date,datetime
from decimal import Decimal

from reporting import day_usage, NS,TEHRAN,cost_report,daily_usage,jalali,local_day,month_start


def number(value):
    return f"{value:,.0f}"


def gb(value):
    return f"{Decimal(value)/10**9:,.2f}"


def timestamp(value):
    if not value:
        return "هنوز گزارشی دریافت نشده"
    dt=datetime.fromtimestamp(value/NS,TEHRAN)
    return f"{jalali(dt.date())}، {dt:%H:%M}"


def overview(db, selected=None, *, migrated=100, retained_rent=0):
    if not 0 <= migrated <= 100 or not 0 <= retained_rent <= 100:
        raise ValueError('Invalid scenario percentage')
    now=time.time_ns()
    today=local_day(now)
    end=min(today,date.fromisoformat(selected)) if selected else today
    start=month_start(end)
    body=[f'<p>دورهٔ شمسی {jalali(start)} تا {jalali(end)} · مبالغ به تومان</p>',
          '<form method="get"><label>تاریخ پایان گزارش به شمسی <input inputmode="numeric" name="end" value="'+jalali(end)+'" placeholder="۱۴۰۵-۰۹-۰۶"></label><button>نمایش گزارش</button></form>']
    estimated_cost=Decimal(0)
    network_bytes=0
    exits={}
    for host,label,delivery in db.execute("SELECT id,label,last_delivery_ns FROM hosts ORDER BY label"):
        cursor=db.execute("SELECT * FROM tariffs WHERE host=? ORDER BY effective",(host,))
        fields=[entry[0] for entry in cursor.description]
        tariffs=[dict(zip(fields,row)) for row in cursor]
        for tariff in tariffs:
            tariff["effective"]=date.fromisoformat(tariff["effective"])
        snapshots=db.execute("SELECT captured_ns,boot_id,interface,ifindex,rx,tx FROM snapshots WHERE host=? ORDER BY captured_ns",(host,))
        usage=daily_usage(snapshots)
        for entry_day,rx,tx in db.execute(
            "SELECT day,quantity,uploaded FROM entries WHERE host=? AND kind='opening' AND day<=?",
            (host,end.isoformat()),
        ):
            key=date.fromisoformat(entry_day)
            if key not in usage:
                usage[key]={**day_usage(),"rx":rx,"tx":tx,"manual":True}
        last=db.execute("SELECT MAX(captured_ns) FROM snapshots WHERE host=?",(host,)).fetchone()[0]
        totals,days=cost_report(usage,tariffs,start,end,now)
        body.append(f'<section><h2>{html.escape(label)}</h2><p>آخرین نمونه {timestamp(last)} · آخرین ارسال {timestamp(delivery)}</p>')
        if not days:
            body.append("<p>برای این دوره تعرفه ثبت نشده است.</p></section>")
            continue
        desc={"free":"ترافیک رایگان","download":"آپلود رایگان","upload":"دانلود رایگان","shared":"سهمیهٔ مشترک دانلود و آپلود"}
        applicable=[t for t in tariffs if t["effective"]<=end][-1]
        body.append(f'<p>{desc[applicable["direction"]]} · سهمیهٔ باقی‌مانده {gb(totals["remaining"])} گیگابایت</p>')
        body.append(f'<p>دانلود {gb(totals["rx"])} · آپلود {gb(totals["tx"])} · مجموع {gb(totals["rx"]+totals["tx"])} گیگابایت</p>')
        body.append(f'<p>تحت سهمیه {gb(totals["included"])} · مازاد {gb(totals["over"])} گیگابایت</p>')
        body.append(f'<p>هزینهٔ تخمینی ترافیک {number(totals["traffic_cost"])} · اجاره {number(totals["rent"])} · جمع {number(totals["traffic_cost"]+totals["rent"])}</p>')
        cost=totals["traffic_cost"]+totals["rent"]
        estimated_cost+=cost
        network_bytes+=totals["rx"]+totals["tx"]
        if host in ("nl","netcup"):
            exits[host]=(usage,tariffs,totals)
        billed=db.execute("SELECT SUM(amount) FROM entries WHERE kind='invoice' AND host=? AND day BETWEEN ? AND ?",
                          (host,start.isoformat(),end.isoformat())).fetchone()[0]
        if billed is not None:
            body.append(f'<p>فاکتورهای ثبت‌شده در بازه {number(billed)} تومان · اختلاف با برآورد {number(billed-cost)} تومان</p>')
        visible_days = [
            item for item in days
            if item[1].get("covered_ns") or item[1].get("manual")
            or item[1].get("rx") or item[1].get("tx")
        ]
        if not visible_days:
            body.append('<p>هنوز نمونه‌ای برای نمایش روزانه دریافت نشده است.</p>')
        else:
            body.append('<details><summary>جزئیات روزانه</summary><table><tr><th>روز</th><th>دانلود GB</th><th>آپلود GB</th><th>وضعیت اندازه‌گیری</th></tr>')
        for day,used,_,_ in reversed(visible_days):
            state="کامل"
            if not used["covered_ns"] or used["gap"] or used["covered_ns"]<86400*NS:
                state="پوشش ناقص"
            if used["estimated"]:
                state+=" · تقسیم تقریبی بین روزها"
            if used.get("manual"):
                state="ثبت دستی"
            body.append(f'<tr><td>{jalali(day)}</td><td>{gb(used["rx"])}</td><td>{gb(used["tx"])}</td><td>{state}</td></tr>')
        if visible_days:
            body.append("</table></details></section>")
    body.insert(1,f'<p>جمع ترافیک رابط‌های سرورها {gb(network_bytes)} GB · جمع هزینهٔ تخمینی {number(estimated_cost)} تومان</p>')
    if len(exits)==2:
        nl_usage,nl_tariffs,nl=exits["nl"]
        nc_usage,nc_tariffs,nc=exits["netcup"]
        left={}
        moved={}
        for day in nl_usage.keys() | nc_usage.keys():
            original=nl_usage.get(day,day_usage())
            destination=nc_usage.get(day,day_usage())
            share=migrated if start<=day<=end else 0
            left[day]={}
            moved[day]={}
            for key in ("rx","tx"):
                transferred=original[key]*share//100
                left[day][key]=original[key]-transferred
                moved[day][key]=destination[key]+transferred
        nl_alt,_=cost_report(left,nl_tariffs,start,end,now)
        nc_alt,_=cost_report(moved,nc_tariffs,start,end,now)
        alternative=(estimated_cost-nl["traffic_cost"]-nc["traffic_cost"]-nl["rent"]
                     +nl_alt["traffic_cost"]+nc_alt["traffic_cost"]+nl["rent"]*retained_rent/100)
        body.append(f'<details><summary>مقایسهٔ هلند و نت‌کاپ برای همین دوره</summary>'
                    f'<form method="get"><input type="hidden" name="end" value="{end.isoformat()}">'
                    f'<label>درصد ترافیک هلند منتقل‌شده به نت‌کاپ<input type="number" min="0" max="100" name="migrated" value="{migrated}"></label>'
                    f'<label>درصد اجارهٔ هلند که همچنان پرداخت می‌شود<input type="number" min="0" max="100" name="retained" value="{retained_rent}"></label>'
                    f'<button>محاسبهٔ سناریو</button></form><p>هزینهٔ چهار سرور {number(estimated_cost)} · سناریوی جایگزین {number(alternative)} · صرفه‌جویی {number(estimated_cost-alternative)} تومان</p>'
                    '<p>محاسبه بر پایهٔ مصرف ثبت‌شدهٔ همین دوره است.</p></details>')
    sold,revenue=db.execute(
        "SELECT COALESCE(SUM(quantity),0),COALESCE(SUM(amount),0) FROM entries WHERE kind='sale' AND day BETWEEN ? AND ?",
        (start.isoformat(),end.isoformat())).fetchone()
    sold_gb=Decimal(sold)/(10**9)
    body.append(f'<section><h2>فروش عمده</h2><p>حجم فروخته‌شده {gb(sold)} گیگابایت · درآمد ثبت‌شده {number(revenue)} تومان</p>')
    if sold_gb:
        body.append(f'<p>قیمت سربه‌سر هر گیگ {number(estimated_cost/sold_gb)} تومان · سود یا زیان با درآمد ثبت‌شده {number(revenue-estimated_cost)} تومان</p>')
        body.append(f'<p>سود یا زیان با نرخ ۲٬۳۵۰ تومان برای هر گیگ فروخته‌شده {number(sold_gb*2350-estimated_cost)} تومان</p>')
    else:
        body.append('<p>برای محاسبهٔ قیمت سربه‌سر، حجم فروش را ثبت کنید.</p>')
    return "".join(body)+"</section>"
