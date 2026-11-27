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


def overview(db, selected=None):
    now=time.time_ns()
    today=local_day(now)
    end=min(today,date.fromisoformat(selected)) if selected else today
    start=month_start(end)
    body=[f'<p>دورهٔ شمسی {jalali(start)} تا {jalali(end)} · مبالغ به تومان</p>',
          '<form method="get"><label>تاریخ پایان گزارش <input type="date" name="end" value="'+end.isoformat()+'"></label><button>نمایش</button></form>']
    estimated_cost=Decimal(0)
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
        billed=db.execute("SELECT SUM(amount) FROM entries WHERE kind='invoice' AND host=? AND day BETWEEN ? AND ?",
                          (host,start.isoformat(),end.isoformat())).fetchone()[0]
        if billed is not None:
            body.append(f'<p>فاکتورهای ثبت‌شده در بازه {number(billed)} تومان · اختلاف با برآورد {number(billed-cost)} تومان</p>')
        body.append('<details><summary>جزئیات روزانه</summary><table><tr><th>روز</th><th>دانلود GB</th><th>آپلود GB</th><th>وضعیت اندازه‌گیری</th></tr>')
        for day,used,_,_ in reversed(days):
            state="کامل"
            if not used["covered_ns"] or used["gap"] or used["covered_ns"]<86400*NS:
                state="پوشش ناقص"
            if used["estimated"]:
                state+=" · تقسیم تقریبی بین روزها"
            if used.get("manual"):
                state="ثبت دستی"
            body.append(f'<tr><td>{jalali(day)}</td><td>{gb(used["rx"])}</td><td>{gb(used["tx"])}</td><td>{state}</td></tr>')
        body.append("</table></details></section>")
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
