import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from watcher import Engine, LiveSystem

def trained(n=80):
    e = Engine("demo", learn_windows=n)
    for _ in range(n): e.step()
    assert e.model is not None
    return e

def test_normal_traffic_mostly_quiet():
    e = trained(); fp = sum(e.step()["anomaly"] for _ in range(100))
    assert fp <= 5, fp

def test_attacks_detected_and_explained():
    e = trained()
    for kind, word in [("scan", "Balayage"), ("exfil", "Exfiltration"), ("flood", "flood")]:
        e.source.inject(kind, 2); pts = [e.step() for _ in range(2)]
        assert any(p["anomaly"] for p in pts), kind
        assert word.lower() in e.alerts[0].title.lower() and e.alerts[0].reasons
        for _ in range(3): e.step()

def test_live_source_reads_proc():
    conns = LiveSystem().window(); assert isinstance(conns, list) and conns
