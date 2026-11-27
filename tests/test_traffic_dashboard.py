"""Regression coverage for traffic measurement, billing and delivery."""
import sqlite3
import sys
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "traffic-dashboard"))
import ingestion
import reporting
from dashboard import configure
from manage import backup, register


def test_measurement_across_jalali_month_and_reboot():
    first = date(2026, 11, 22)
    start = reporting.midnight(first)
    ns = reporting.NS
    rows = [
        (start-10*ns, "boot1", "eth0", 2, "90", "800"),
        (start+10*ns, "boot1", "eth0", 2, "101", "820"),
        (start+20*ns, "boot2", "eth0", 2, "3", "5"),
    ]
    days = reporting.daily_usage(rows)
    assert reporting.jalali(first) == "1405-09-01"
    assert days[first-timedelta(days=1)]["rx"] == 5
    assert days[first]["rx"] == 6
    assert days[first]["tx"] == 10
    assert days[first]["estimated"] and days[first]["gap"]


def test_provider_allowance_survives_reporting_month_boundary():
    day = date(2026, 11, 22)
    unit = 10**9
    tariff = dict(effective=date(2026,11,1), calendar="gregorian", reset=1,
                  direction="download", allowance=1, unit=unit, mode="hourly", rent=10, rate=322)
    usage = {day-timedelta(days=1): dict(rx=unit, tx=0), day:dict(rx=unit, tx=2*unit)}
    totals,_ = reporting.cost_report(usage,[tariff],day,day,reporting.midnight(day+timedelta(days=1)))
    assert totals["traffic_cost"] == 322
    assert totals["rent"] == 240
    assert totals["over"] == unit


def test_ingest_rollback_and_backup(tmp_path):
    with closing(sqlite3.connect(tmp_path/"dashboard")) as db:
        configure(db)
        register(db,"ir",tmp_path/"key")
        token=(tmp_path/"key").read_text()
        sample=dict(captured_ns=3,rx=str(2**64-1),tx="123",ifindex=2,interface="eth0",
                    boot_id="12345678-1234-1234-1234-123456789abc")
        batch=dict(server="ir",samples=[sample])
        assert ingestion.accept(db,token,batch)==ingestion.accept(db,token,batch)
        with pytest.raises(PermissionError):
            ingestion.accept(db,"invalid",batch)
        with pytest.raises(ValueError):
            ingestion.accept(db,token,dict(server="ir",samples=[dict(sample,captured_ns=2),dict(sample,tx="0")]))
        backup(tmp_path/"dashboard",tmp_path/"backup")
    backup(tmp_path/"backup",tmp_path/"restored")
    with closing(sqlite3.connect(tmp_path/"restored")) as db:
        assert db.execute("SELECT captured_ns,rx FROM snapshots").fetchall()==[(3,str(2**64-1))]
