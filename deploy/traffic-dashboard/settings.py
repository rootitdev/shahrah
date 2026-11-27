"""Administrative forms and append-only change journal."""
import csv
import html
import io
import json
import re
import time
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from reporting import TEHRAN, jalali, midnight

esc = html.escape
GB = 10**9


def initialize_settings(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS entries(
            host TEXT NOT NULL,day TEXT NOT NULL,kind TEXT NOT NULL,
            amount INTEGER NOT NULL DEFAULT 0, quantity INTEGER NOT NULL DEFAULT 0,
            uploaded INTEGER NOT NULL DEFAULT 0,note TEXT NOT NULL,
            PRIMARY KEY(host,day,kind));
        CREATE TABLE IF NOT EXISTS journal(
            id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,actor TEXT NOT NULL,
            action TEXT NOT NULL, details TEXT NOT NULL);
    """)


def integer(form, key, upper=10**15):
    value = int(form[key])
    if not 0 <= value <= upper:
        raise ValueError("invalid amount")
    return value


def volume(form,key):
    try:
        amount=Decimal(form[key])*GB
        if not amount.is_finite() or not 0<=amount<=2**63-1 or amount!=amount.to_integral_value():
            raise ValueError("invalid volume")
        return int(amount)
    except InvalidOperation as exc:
        raise ValueError("invalid volume") from exc


def save(db,form,actor):
    action=form["action"]
    host=form.get("host","")
    if action!="sale" and not db.execute("SELECT 1 FROM hosts WHERE id=?",(host,)).fetchone():
        raise ValueError("unknown host")
    day=date.fromisoformat(form["day"])
    if not date(2000,1,1)<=day<=date(2100,12,31):
        raise ValueError("invalid date")
    dt=day.isoformat()
    note=form.get("note","").strip()
    if not note or len(note)>300:
        raise ValueError("note required")
    with db:
        if action=="tariff":
            mode, direction, calendar=form["mode"],form["direction"],form["calendar"]
            reset=integer(form,"reset",28)
            unit=int(form["unit"])
            if (mode not in ("monthly","hourly") or direction not in ("free","upload","download","shared")
                    or calendar not in ("gregorian","jalali") or not reset or unit not in (GB,2**30)):
                raise ValueError("invalid tariff")
            db.execute("""INSERT INTO tariffs VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(host,effective) DO UPDATE SET direction=excluded.direction,
                allowance=excluded.allowance,rate=excluded.rate,mode=excluded.mode,rent=excluded.rent,
                unit=excluded.unit,calendar=excluded.calendar,reset=excluded.reset""",
                (host,dt,direction,integer(form,"allowance",10**9),integer(form,"rate"),mode,
                 integer(form,"rent"),unit,calendar,reset))
        elif action in ("invoice","sale","opening"):
            if day>datetime.now(TEHRAN).date():
                raise ValueError("future actual")
            if action=="opening":
                first=db.execute("SELECT MIN(captured_ns) FROM snapshots WHERE host=?",(host,)).fetchone()[0]
                if first is not None and midnight(day)+86400*10**9>first:
                    raise ValueError("manual usage overlaps measurement")
            amount=integer(form,"amount") if action!="opening" else 0
            quantity=volume(form,"quantity") if action!="invoice" else 0
            uploaded=volume(form,"uploaded") if action=="opening" else 0
            db.execute("""INSERT INTO entries VALUES(?,?,?,?,?,?,?) ON CONFLICT(host,day,kind)
                DO UPDATE SET amount=excluded.amount,quantity=excluded.quantity,
                uploaded=excluded.uploaded,note=excluded.note""",
                ("" if action=="sale" else host,dt,action,amount,quantity,uploaded,note))
        elif action=="label":
            label=form["label"].strip()
            if not 1<=len(label)<=80:
                raise ValueError("invalid label")
            db.execute("UPDATE hosts SET label=? WHERE id=?",(label,host))
        else:
            raise ValueError("unknown action")
        db.execute("INSERT INTO journal(ts,actor,action,details) VALUES(?,?,?,?)",
                   (int(time.time()),actor,action,json.dumps(form,ensure_ascii=False)))


def options(items,current):
    return "".join(f'<option value="{esc(str(k))}" {"selected" if k==current else ""}>{esc(str(v))}</option>' for k,v in items)


def field(label,name,value="",kind="text"):
    return f'<label>{label}<input required type="{kind}" name="{name}" value="{esc(str(value))}"></label>'


def select(label,name,items,current):
    return f'<label>{label}<select name="{name}">{options(items,current)}</select></label>'


def settings(db):
    today=datetime.now(TEHRAN).date().isoformat()
    def form(action,host,body):
        return (f'<form method="post" action="/settings"><input type="hidden" name="action" value="{action}">'
                f'<input type="hidden" name="host" value="{esc(host)}">'+field("تاریخ اثر","day",today,"date")
                +body+field("توضیح ثبت یا اصلاح","note")+'<button>ذخیره</button></form>')
    out=['<nav><a href="/">گزارش مصرف</a> · <a href="/export">خروجی CSV نمونه‌ها</a></nav>']
    out.append('<details><summary>حجم و درآمد فروش روزانه</summary><p>ثبت دوباره برای همان روز، جمع روز را اصلاح می‌کند.</p>'+
               form("sale","",field("گیگابایت فروخته‌شده","quantity")+field("درآمد کل روز (تومان)","amount",0,"number"))+'</details>')
    for host,label in db.execute("SELECT id,label FROM hosts ORDER BY label"):
        t=db.execute("SELECT direction,allowance,rate,mode,rent,unit,calendar,reset FROM tariffs WHERE host=? AND effective<=? ORDER BY effective DESC LIMIT 1",(host,today)).fetchone()
        if not t:
            continue
        out.append(f'<section><h2>{esc(label)}</h2><details><summary>تعرفه و دورهٔ ارائه‌دهنده</summary>'+
            form("tariff",host,select("جهت مشمول","direction",(("shared","جمع دانلود و آپلود"),("download","فقط دانلود"),("upload","فقط آپلود"),("free","هر دو رایگان")),t[0])
                 +field("سهمیهٔ هر دوره","allowance",t[1],"number")+field("نرخ هر واحد اضافه (تومان)","rate",t[2],"number")
                 +select("اجاره","mode",(("hourly","ساعتی"),("monthly","ماهانه")),t[3])+field("نرخ اجاره (تومان)","rent",t[4],"number")
                 +select("واحد ارائه‌دهنده","unit",((GB,"GB"),(2**30,"GiB")),t[5])
                 +select("تقویم قبض","calendar",(("jalali","شمسی"),("gregorian","میلادی")),t[6])
                 +field("روز شروع دوره (۱ تا ۲۸)","reset",t[7],"number"))+'</details>')
        out.append('<details><summary>مبلغ فاکتور</summary><p>مجموع فاکتورهای این سرور در تاریخ ثبت را وارد کنید.</p>'+
                   form("invoice",host,field("تومان","amount",0,"number"))+'</details>')
        out.append('<details><summary>مصرف تاریخی پیش از نصب</summary>'+
                   form("opening",host,field("دانلود GB","quantity")+field("آپلود GB","uploaded"))+'</details>')
        out.append('<details><summary>نام نمایشی</summary>'+form("label",host,field("نام سرور","label",label))+'</details></section>')
    out.append('<details><summary>تاریخچهٔ تغییرات اخیر</summary><ol>')
    for stamp,action,details in db.execute("SELECT ts,action,details FROM journal ORDER BY id DESC LIMIT 100"):
        record=json.loads(details)
        out.append(f'<li>{jalali(datetime.fromtimestamp(stamp,TEHRAN).date())} · {esc(record.get("host",""))} · {esc(action)} · {esc(record["note"])}</li>')
    return "".join(out)+"</ol></details>"


def snapshot_csv(db):
    buf=io.StringIO(newline="")
    writer=csv.writer(buf)
    writer.writerow(("server","captured_ns","boot_id","interface","ifindex","rx_bytes","tx_bytes"))
    writer.writerows(db.execute("SELECT * FROM snapshots ORDER BY host,captured_ns"))
    return buf.getvalue().encode("utf-8-sig")
