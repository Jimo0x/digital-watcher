"""Digital Watcher — apprentissage du comportement normal et détection d'anomalies.

Une « fenêtre » résume l'activité réseau sur quelques secondes (volumes,
nombre de connexions, diversité des destinations…). Après une phase
d'apprentissage, un IsolationForest note chaque nouvelle fenêtre ; les écarts
par rapport à la base apprise servent à expliquer l'alerte en français.
"""
from __future__ import annotations

import ipaddress
import random
import socket
import struct
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = [
    ("bytes_out", "Volume sortant", "Ko"),
    ("bytes_in", "Volume entrant", "Ko"),
    ("conns", "Connexions", ""),
    ("uniq_ips", "Destinations distinctes", ""),
    ("uniq_ports", "Ports distincts", ""),
    ("new_dst", "Destinations jamais vues", ""),
    ("half_open", "Connexions en attente (SYN)", ""),
    ("bytes_per_conn", "Octets par connexion", "Ko"),
]


@dataclass
class Conn:
    dst: str
    port: int
    out: float = 0.0  # octets
    inn: float = 0.0
    state: str = "EST"


# ───────────────────────── sources de données ─────────────────────────
class Simulator:
    """Trafic d'un poste « normal » + attaques injectables à la demande."""

    NORMAL = [("142.250.74.110", 443), ("151.101.1.140", 443), ("104.16.132.229", 443), ("140.82.112.4", 443),
              ("17.253.144.10", 443), ("52.97.146.162", 443), ("8.8.8.8", 53), ("1.1.1.1", 53), ("185.199.108.153", 443)]

    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)
        self.attack: str | None = None
        self.attack_left = 0
        self.beacon_ip = "203.0.113.66"

    def inject(self, kind: str, windows: int = 6) -> None:
        self.attack, self.attack_left = kind, windows

    def window(self) -> list[Conn]:
        r = self.rng
        busy = 1.0 + 0.6 * np.sin(time.time() / 40)
        conns = []
        for _ in range(max(2, int(r.gauss(14, 3) * busy))):
            ip, port = r.choice(self.NORMAL)
            out = r.lognormvariate(7.5, 0.8)
            conns.append(Conn(ip, port, out, out * r.uniform(3, 12)))
        if self.attack_left > 0:
            self.attack_left -= 1
            k = self.attack
            if k == "scan":
                target = "10.0.0." + str(r.randint(2, 250))
                conns += [Conn(target, p, 60, 0, "SYN") for p in r.sample(range(1, 65535), 180)]
            elif k == "exfil":
                conns.append(Conn("198.51.100." + str(r.randint(2, 250)), 443, r.uniform(40e6, 90e6), 2e4))
            elif k == "beacon":
                conns += [Conn(self.beacon_ip, 8443, 400, 300) for _ in range(30)]
            elif k == "flood":
                conns += [Conn(f"192.0.2.{r.randint(1, 254)}", 80, 80, r.uniform(2e5, 6e5)) for _ in range(260)]
            elif k == "dns_tunnel":
                conns += [Conn("8.8.4.4", 53, r.uniform(200, 400), 150) for _ in range(140)]
        return conns


TCP_STATES = {"01": "EST", "02": "SYN", "03": "SYN", "06": "TIME_WAIT", "08": "CLOSE_WAIT", "0A": "LISTEN"}


class LiveSystem:
    """Lit les connexions et compteurs réels de la machine (Linux : /proc)."""

    def __init__(self) -> None:
        self.prev = self._dev()

    @staticmethod
    def _dev() -> tuple[int, int]:
        rx = tx = 0
        try:
            for line in open("/proc/net/dev").read().splitlines()[2:]:
                name, data = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                v = data.split()
                rx += int(v[0])
                tx += int(v[8])
        except OSError:
            pass
        return rx, tx

    @staticmethod
    def _hex_ip(h: str) -> str:
        if len(h) == 8:
            return socket.inet_ntoa(struct.pack("<I", int(h, 16)))
        b = bytes.fromhex(h)
        return str(ipaddress.IPv6Address(b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))))

    def window(self) -> list[Conn]:
        conns = []
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                for line in open(f).read().splitlines()[1:]:
                    p = line.split()
                    rip, rport = p[2].split(":")
                    st = TCP_STATES.get(p[3], "OTHER")
                    if st == "LISTEN" or int(rport, 16) == 0:
                        continue
                    ip = self._hex_ip(rip)
                    if ip.startswith("127.") or ip == "::1":
                        continue
                    conns.append(Conn(ip, int(rport, 16), 0, 0, st))
            except OSError:
                continue
        rx, tx = self._dev()
        drx, dtx = rx - self.prev[0], tx - self.prev[1]
        self.prev = (rx, tx)
        if conns:  # on répartit les volumes de l'interface sur les connexions actives
            for c in conns:
                c.out, c.inn = dtx / len(conns), drx / len(conns)
        else:
            conns.append(Conn("—", 0, dtx, drx, "IDLE"))
        return conns


# ───────────────────────── moteur ─────────────────────────
@dataclass
class Alert:
    t: float
    score: float
    severity: str
    title: str
    reasons: list[str]
    top: list[tuple[str, int]] = field(default_factory=list)


class Engine:
    def __init__(self, source: str = "demo", period: float = 1.0, learn_windows: int = 60, sensitivity: float = 0.5):
        self.source_name = source
        self.source = Simulator() if source == "demo" else LiveSystem()
        self.period = period
        self.learn_windows = learn_windows
        self.sensitivity = sensitivity
        self.history: deque = deque(maxlen=240)
        self.baseline: list[list[float]] = []
        self.model: IsolationForest | None = None
        self.mu = self.sd = None
        self.threshold = 0.0
        self.seen_dst: set[str] = set()
        self.seen_ports: Counter = Counter()
        self.alerts: deque = deque(maxlen=100)
        self.top_dst: Counter = Counter()
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.thread: threading.Thread | None = None

    # -- extraction des caractéristiques
    def features(self, conns: list[Conn]) -> tuple[list[float], dict]:
        ips = {c.dst for c in conns}
        new = ips - self.seen_dst if self.model else set()
        out = sum(c.out for c in conns) / 1024
        inn = sum(c.inn for c in conns) / 1024
        f = [out, inn, len(conns), len(ips), len({c.port for c in conns}), len(new),
             sum(c.state == "SYN" for c in conns), (out + inn) / max(1, len(conns))]
        per_ip = Counter(c.dst for c in conns)
        meta = {"new": sorted(new)[:5], "heavy_new": [ip for ip in new if per_ip[ip] >= 10], "ports": Counter(c.port for c in conns).most_common(3),
                "dst": Counter(c.dst for c in conns).most_common(5)}
        return f, meta

    def step(self) -> dict:
        conns = self.source.window()
        f, meta = self.features(conns)
        point = {"t": time.time(), "f": f, "score": None, "anomaly": False}
        with self.lock:
            self.top_dst.update({ip: n for ip, n in meta["dst"]})
            if self.model is None:
                self.baseline.append(f)
                self.seen_dst |= {c.dst for c in conns}
                self.seen_ports.update(c.port for c in conns)
                if len(self.baseline) >= self.learn_windows:
                    self._train()
            else:
                s = float(self._score(np.log1p(np.array([f])))[0])
                point["score"] = s
                if meta["heavy_new"]:  # règle : une destination inconnue contactée en rafale
                    s = max(s, self.threshold + 0.035)
                point["score"] = s
                if s > self.threshold:
                    point["anomaly"] = True
                    self._alert(f, s, meta)
                else:  # adaptation lente : seules les fenêtres normales enrichissent la base
                    self.seen_dst |= {c.dst for c in conns}
                    self.baseline.append(f)
                    if len(self.baseline) % 120 == 0:
                        self._train()
            self.history.append(point)
        return point

    def _train(self) -> None:
        base = np.log1p(np.array(self.baseline[-600:]))
        self.model = IsolationForest(n_estimators=150, contamination="auto", random_state=0).fit(base)
        self.mu, self.sd = base.mean(0), np.maximum(base.std(0), 0.25)
        scores = self._score(base)
        q = 0.995 - 0.03 * self.sensitivity  # sensibilité ↑ ⇒ seuil ↓
        self.threshold = float(np.quantile(scores, q) + 0.04 * (1 - self.sensitivity))

    def _score(self, X: np.ndarray) -> np.ndarray:
        """Score hybride : isolation (forêt) + écart robuste maximal par caractéristique.

        L'Isolation Forest sature pour les points très éloignés ; le terme en z
        garantit qu'une valeur extrême (×50 sur un volume) ressorte nettement.
        """
        iso = -self.model.score_samples(X)
        z = np.abs((X - self.mu) / self.sd).max(axis=1)
        return iso + 0.04 * np.clip(z - 3, 0, 20)

    def _alert(self, f: list[float], s: float, meta: dict) -> None:
        z = (np.log1p(np.array(f)) - self.mu) / self.sd
        reasons, base_lin = [], np.expm1(self.mu)
        for i in np.argsort(-np.abs(z))[:3]:
            if abs(z[i]) < 2.5:
                continue
            key, label, unit = FEATURES[i]
            ratio = (f[i] + 1) / (base_lin[i] + 1)
            way = f"× {ratio:.1f}" if ratio >= 1 else f"÷ {1 / ratio:.1f}"
            reasons.append(f"{label} : {f[i]:,.0f}{' ' + unit if unit else ''} ({way} par rapport à la normale ≈ {base_lin[i]:,.0f})".replace(",", " "))
        if meta["new"]:
            reasons.append("Nouvelles destinations : " + ", ".join(meta["new"]))
        title = self._classify(f, z)
        if meta.get("heavy_new") and title == "Comportement inhabituel" or meta.get("heavy_new") and f[4] <= 3 and f[3] < 30:
            title = "Beaconing vers un hôte inconnu (C2 possible)"
            reasons.insert(0, f"{len(meta['heavy_new'])} hôte(s) jamais vu(s) contacté(s) plus de 10 fois dans la fenêtre")
        if meta["ports"] and meta["ports"][0][0] == 53 and meta["ports"][0][1] > 60:
            title = "Tunnel DNS possible (rafale de requêtes DNS)"
        sev = "critique" if s > self.threshold + 0.08 else "élevée" if s > self.threshold + 0.03 else "moyenne"
        self.alerts.appendleft(Alert(time.time(), round(s, 3), sev, title, reasons or ["Combinaison inhabituelle de caractéristiques."], meta["dst"][:3]))

    @staticmethod
    def _classify(f, z) -> str:
        bo, bi, conns, ips, ports, new, syn, bpc = f
        if ports > 50 and syn > 20:
            return "Balayage de ports probable"
        if z[0] > 4 and bpc > 1000:
            return "Exfiltration de données possible"
        if ips > 40 and z[1] > 3:
            return "Afflux de trafic entrant (flood)"
        if conns > 60 and ports <= 3:
            return "Rafale de requêtes vers un même service (tunnel / beaconing)"
        if new:
            return "Communication avec des destinations inconnues"
        return "Comportement inhabituel"

    # -- boucle d'arrière-plan
    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self._stop.clear()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.step()
            except Exception as e:  # pragma: no cover
                print("watcher:", e)
            self._stop.wait(self.period)

    def state(self) -> dict:
        with self.lock:
            return {
                "source": self.source_name,
                "phase": "surveillance" if self.model else "apprentissage",
                "progress": min(1.0, len(self.baseline) / self.learn_windows) if not self.model else 1.0,
                "threshold": round(self.threshold, 3),
                "sensitivity": self.sensitivity,
                "features": [{"key": k, "label": l, "unit": u} for k, l, u in FEATURES],
                "history": [{"t": p["t"], "f": [round(v, 1) for v in p["f"]], "score": p["score"], "anomaly": p["anomaly"]} for p in self.history],
                "alerts": [a.__dict__ for a in self.alerts],
                "top": self.top_dst.most_common(8),
                "known": len(self.seen_dst),
            }
