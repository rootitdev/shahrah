"""Measured public-interface usage by Tehran day and Jalali reporting month."""
from collections import defaultdict
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

TEHRAN = ZoneInfo("Asia/Tehran")
NS = 1_000_000_000
def gregorian_to_jalali(gy: int, gm: int, gd: int) -> tuple[int, int, int]:
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = (
        355666
        + 365 * gy
        + (gy2 + 3) // 4
        - (gy2 + 99) // 100
        + (gy2 + 399) // 400
        + gd
        + g_d_m[gm - 1]
    )
    jy = -1595 + 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm = 1 + days // 31
        jd = 1 + days % 31
    else:
        jm = 7 + (days - 186) // 30
        jd = 1 + (days - 186) % 30
    return jy, jm, jd


def local_day(stamp):
    return datetime.fromtimestamp(stamp // NS, TEHRAN).date()


def midnight(day):
    return int(datetime.combine(day, time(), TEHRAN).timestamp()) * NS


def jalali(day):
    y, m, d = gregorian_to_jalali(day.year, day.month, day.day)
    return f"{y:04}-{m:02}-{d:02}"


def jalali_to_gregorian(text):
    parts = text.strip().replace("/", "-").split("-")
    if len(parts) != 3:
        raise ValueError("Invalid Jalali date")
    jy, jm, jd = (int(part) for part in parts)
    if not 1 <= jm <= 12 or not 1 <= jd <= (31 if jm <= 6 else 30):
        raise ValueError("Invalid Jalali date")
    jy -= 979
    days = 365 * jy + (jy // 33) * 8 + ((jy % 33) + 3) // 4
    days += (jm - 1) * 31 if jm <= 7 else (jm - 1) * 30 + 6
    days += jd - 1 + 79
    gy = 1600 + 400 * (days // 146097)
    days %= 146097
    leap = True
    if days >= 36525:
        days -= 1
        gy += 100 * (days // 36524)
        days %= 36524
        if days >= 365:
            days += 1
        else:
            leap = False
    gy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        leap = False
        days -= 1
        gy += days // 365
        days %= 365
    gd = days + 1
    month_days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    gm = 1
    while gd > month_days[gm - 1]:
        gd -= month_days[gm - 1]
        gm += 1
    return date(gy, gm, gd)


def day_usage():
    return {"rx": 0, "tx": 0, "estimated": False, "gap": False, "covered_ns": 0}


def daily_usage(samples):
    """Accept timestamp-ordered tuples (ns, boot, interface, index, rx, tx).
    Split boundary crossings proportionally, conserving integer bytes exactly.
    Never extrapolate a counter delta across incompatible baselines.
    """
    result = defaultdict(day_usage)
    previous = None
    for current in samples:
        if previous is None:
            previous = current
            result[local_day(current[0])]
            continue
        start, end = previous[0], current[0]
        duration = end - start
        if duration <= 0:
            raise ValueError("Snapshots must be in chronological order")
        rx = int(current[4]) - int(previous[4])
        tx = int(current[5]) - int(previous[5])
        comparable = previous[1:4] == current[1:4] and min(rx, tx) >= 0
        cursor = start
        while cursor < end:
            day = local_day(cursor)
            stop = min(end, midnight(day + timedelta(days=1)))
            data = result[day]
            if comparable:
                for key, delta in (("rx", rx), ("tx", tx)):
                    data[key] += delta * (stop-start)//duration - delta * (cursor-start)//duration
                data["covered_ns"] += stop - cursor
                data["estimated"] |= stop != end or cursor != start
            data["gap"] |= not comparable or duration > 13*3600*NS
            cursor = stop
        previous = current
    return result


def month_start(day):
    jd = gregorian_to_jalali(day.year, day.month, day.day)[2]
    return day - timedelta(days=jd-1)


def cycle_start(day, calendar, reset):
    if calendar == "jalali":
        first = month_start(day)
        if (day-first).days+1 < reset:
            first = month_start(first-timedelta(days=1))
    else:
        first = day.replace(day=1)
        if day.day < reset:
            first = (first-timedelta(days=1)).replace(day=1)
    return first + timedelta(days=reset-1)


def billable(direction, rx, tx):
    return {"shared": rx+tx, "download": rx, "upload": tx, "free": 0}[direction]


def cost_report(usage, tariffs, start, end, through_ns):
    """Report [start,end] days. Tariff revisions preserve usage in a running cycle."""
    totals = defaultdict(Decimal)
    consumed = defaultdict(int)
    days = []
    if not tariffs:
        return totals, days
    day = min(start, min(usage, default=start), tariffs[0]["effective"])
    version = -1
    while day <= end and midnight(day) < through_ns:
        while version+1 < len(tariffs) and tariffs[version+1]["effective"] <= day:
            version += 1
        if version >= 0:
            t = tariffs[version]
            used = usage.get(day, day_usage())
            cycle = cycle_start(day, t["calendar"], t["reset"])
            unit = t["unit"]
            included = t["allowance"] * unit
            amount = billable(t["direction"], used["rx"], used["tx"])
            free = min(amount, max(0, included-consumed[cycle]))
            consumed[cycle] += amount
            if day >= start:
                elapsed = min(midnight(day+timedelta(days=1)), through_ns) - midnight(day)
                rent = (Decimal(t["rent"])*elapsed/(3600*NS) if t["mode"]=="hourly"
                        else Decimal(t["rent"] if day==cycle else 0))
                over = amount-free
                charge = Decimal(over)*t["rate"]/unit
                for key,value in (("rx",used["rx"]),("tx",used["tx"]),("included",free),
                                  ("over",over),("traffic_cost",charge),("rent",rent)):
                    totals[key] += value
                totals["remaining"] = max(0,included-consumed[cycle])
                days.append((day,used,charge,rent))
        day += timedelta(days=1)
    return totals, days
