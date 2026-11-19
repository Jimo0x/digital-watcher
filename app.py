"""Digital Watcher — serveur Flask."""
import os
import sys

from flask import Flask, jsonify, request, send_from_directory

from watcher import Engine

app = Flask(__name__, static_folder="static", static_url_path="")
engine = Engine("demo", period=0.5, learn_windows=60)


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/state")
def state():
    return jsonify(engine.state())


@app.post("/api/config")
def config():
    global engine
    d = request.get_json() or {}
    src = d.get("source", engine.source_name)
    if src == "live" and not sys.platform.startswith("linux"):
        return jsonify({"error": "Le mode « système réel » lit /proc et n'est disponible que sous Linux."}), 400
    if src != engine.source_name or d.get("reset"):
        engine.stop()
        engine = Engine(src, period=0.5 if src == "demo" else 2.0, learn_windows=60 if src == "demo" else 45,
                        sensitivity=float(d.get("sensitivity", engine.sensitivity)))
        engine.start()
    elif "sensitivity" in d:
        engine.sensitivity = float(d["sensitivity"])
        if engine.model:
            engine._train()
    return jsonify({"ok": True})


@app.post("/api/inject/<kind>")
def inject(kind):
    if engine.source_name != "demo":
        return jsonify({"error": "Injection disponible uniquement en mode démo"}), 400
    if kind not in {"scan", "exfil", "beacon", "flood", "dns_tunnel"}:
        return jsonify({"error": "attaque inconnue"}), 400
    engine.source.inject(kind)
    return jsonify({"ok": True})


if __name__ == "__main__":
    engine.start()
    port = int(os.environ.get("PORT", 5004))
    print(f"Digital Watcher → http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, threaded=True)
