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

def test_remote_interface_selection_applies_after_ack(tmp_path):
    import io
    import json
    from collector import capture
    from deliver import deliver

    boot = tmp_path/"boot"
    boot.write_text("12345678-1234-1234-1234-123456789abc")
    for index,name in enumerate(("eth0","ens3"), start=1):
        dev=tmp_path/name
        (dev/"statistics").mkdir(parents=True)
        (dev/"ifindex").write_text(str(index))
        for field in ("rx_bytes", "tx_bytes"):
            (dev/"statistics"/field).write_text("100")
    db=tmp_path/"queue"
    capture(db,"eth0",sysnet=tmp_path,boot_file=boot,now=lambda:1)

    def receiver(req,timeout):
        batch=json.loads(req.data)
        assert batch["interface_settings"] and batch["samples"][0]["interface"]=="eth0"
        return io.BytesIO(b'{"server":"ir","accepted":[1],"interface":"ens3"}')

    deliver(db,"ir","test",send=receiver)
    capture(db,"eth0",sysnet=tmp_path,boot_file=boot,now=lambda:2)
    with closing(sqlite3.connect(db)) as c:
        assert c.execute("SELECT interface FROM samples").fetchall()==[("ens3",)]


def test_report_scenario_keeps_existing_netcup_rent(tmp_path):
    from views import overview
    with closing(sqlite3.connect(":memory:")) as db:
        configure(db)
        for host in ("nl","netcup"):
            register(db,host,tmp_path/host)
        page=overview(db,migrated=100,retained_rent=0)
        assert "سناریوی جایگزین 3,000,000" in page
        with pytest.raises(ValueError):
            overview(db,migrated=101)
