let st = null, seenAlerts = 0;

$$("#src button").forEach(b => b.onclick = async () => {
  try { await api("/api/config", { method: "POST", body: { source: b.dataset.s } }); $$("#src button").forEach(x => x.classList.toggle("on", x === b)); seenAlerts = 0; }
  catch (e) { toast(e.message, 4000); }
});
$("#reset").onclick = () => api("/api/config", { method: "POST", body: { reset: true } }).then(() => { seenAlerts = 0; toast("Apprentissage relancé"); });
$("#sens").oninput = e => $("#sensv").textContent = e.target.value;
$("#sens").onchange = e => api("/api/config", { method: "POST", body: { sensitivity: +e.target.value } });
$$("#attacks button").forEach(b => b.onclick = async () => {
  if (st && st.phase !== "surveillance") return toast("Attendez la fin de l'apprentissage du comportement normal.");
  try { await api("/api/inject/" + b.dataset.a, { method: "POST" }); toast(`Attaque injectée : ${b.textContent}`); } catch (e) { toast(e.message); }
});

async function poll() {
  try { st = await api("/api/state"); render(); } catch (e) { $("#phase").textContent = "hors ligne"; }
  setTimeout(poll, 700);
}
function render() {
  const h = st.history, last = h[h.length - 1];
  $("#phase").innerHTML = st.phase === "surveillance" ? `<span class="okc">Surveillance</span>` : `<span class="warnc">Apprentissage</span> <small class="muted">${Math.round(st.progress * 100)} %</small>`;
  $("#prog").style.width = st.progress * 100 + "%";
  $("#score").innerHTML = last && last.score != null ? `<span class="${last.anomaly ? "red" : ""}">${last.score.toFixed(3)}</span> <small class="muted">/ ${st.threshold}</small>` : "—";
  $("#nAlerts").textContent = st.alerts.length; $("#known").textContent = st.known;
  $("#srcBadge").textContent = st.source === "demo" ? "trafic simulé" : "machine locale";
  $("#attacks").style.opacity = st.source === "demo" ? 1 : .35;

  const scores = h.map(p => p.score ?? 0), marks = h.map((p, i) => p.anomaly ? i : -1).filter(i => i >= 0);
  const lo = Math.min(...scores.filter(Boolean), st.threshold || 0.3) - .05;
  Charts.line($("#chart"), [{ data: scores.map(s => Math.max(0, s - lo)), marks, color: "#e5172f" }, { data: h.map(() => Math.max(0, st.threshold - lo)), color: "#8d8d99", dash: true, fill: false }]);

  if (!$("#feats").children.length) $("#feats").innerHTML = st.features.map((f, i) => `<div class="feat"><div class="l">${f.label}</div><div class="n" id="fv${i}">—</div><canvas id="fc${i}" style="width:100%;height:42px"></canvas></div>`).join("");
  st.features.forEach((f, i) => {
    const series = h.map(p => p.f[i]); if (!series.length) return;
    $("#fv" + i).innerHTML = `${series[series.length - 1].toLocaleString("fr-FR")} <small class="muted">${f.unit}</small>`;
    sparkline($("#fc" + i), series, h.map(p => p.anomaly));
  });
  $("#top").innerHTML = `<tr><th>Destination</th><th>Connexions</th></tr>` + st.top.map(([ip, n]) => `<tr><td class="mono">${esc(ip)}</td><td>${n}</td></tr>`).join("");

  if (st.alerts.length !== seenAlerts) {
    if (st.alerts.length > seenAlerts && seenAlerts) toast("⚠ " + st.alerts[0].title);
    seenAlerts = st.alerts.length;
    $("#alerts").innerHTML = st.alerts.map(a => `<div class="alert ${a.severity}"><div class="row between"><b>${esc(a.title)}</b><span class="badge ${a.severity === "moyenne" ? "warn" : "red"}">${a.severity}</span></div>
      <div class="dim mono" style="font-size:11px">${new Date(a.t * 1000).toLocaleTimeString()} · score ${a.score}</div><ul>${a.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>`).join("")
      || `<div class="empty"><div class="shield">🛡</div>Aucune anomalie. ${st.phase === "apprentissage" ? "Le système apprend le comportement normal…" : "Tout est calme."}</div>`;
  }
}
function sparkline(cv, data, anom) {
  const dpr = devicePixelRatio || 1, w = cv.clientWidth, h = cv.clientHeight; cv.width = w * dpr; cv.height = h * dpr;
  const x = cv.getContext("2d"); x.scale(dpr, dpr); const max = Math.max(...data, 1e-9), n = data.length;
  x.beginPath(); data.forEach((v, i) => { const px = n === 1 ? w / 2 : i / (n - 1) * w, py = h - 3 - v / max * (h - 6); i ? x.lineTo(px, py) : x.moveTo(px, py); });
  x.strokeStyle = "#8d8d99"; x.lineWidth = 1.3; x.stroke();
  x.fillStyle = "#e5172f"; anom.forEach((a, i) => { if (a) { const px = i / Math.max(1, n - 1) * w, py = h - 3 - data[i] / max * (h - 6); x.beginPath(); x.arc(px, py, 2.5, 0, 7); x.fill(); } });
}
poll();
