// Estado de la interfaz. El backend solo empuja eventos; toda la decisión de
// qué mostrar vive acá.
var state = {
  totalArtifacts: 0,
  collectors: {}, // nombre -> li del DOM
  live: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  liveShown: 0,
};

// Tope de nodos en el feed en vivo. Sin esto un escaneo con muchas señales
// degrada el render: el DOM crece sin límite mientras el usuario mira.
var MAX_LIVE_NODES = 300;

var SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

var CATEGORY_LABEL = {
  ANTI_FORENSIC: "Manipulación de rastros",
  PERSISTENCE: "Mecanismos de persistencia",
  EXECUTION: "Evidencia de ejecución",
  EMULATOR: "Emuladores",
  KNOWN_CHEAT: "Cheats conocidos",
};

function show(id) {
  var screens = document.querySelectorAll(".screen");
  for (var i = 0; i < screens.length; i++) screens[i].classList.remove("active");
  document.getElementById(id).classList.add("active");
}

function acceptConsent() {
  show("screen-scan");
  document.getElementById("topbar-status").textContent = "Analizando";
  document.getElementById("statusbar").classList.add("on");
  setScanning(true);
  window.startScan();
}

// setScanning enciende o apaga las señales de actividad. Van juntas a
// propósito: si una queda animando cuando el escaneo terminó, la interfaz
// miente sobre lo que está pasando.
function setScanning(on) {
  document.getElementById("wave").hidden = !on;
  document.getElementById("brand-dot").classList.toggle("live", on);
  document.getElementById("sweep").classList.toggle("on", on);
  document.getElementById("statusbar").classList.toggle("on", on);
}

// countUp anima un número de su valor actual al nuevo. Un contador que salta
// de 0 a 1247 no se lee; uno que sube deja ver que algo está pasando.
function countUp(el, to) {
  var from = parseInt(el.getAttribute("data-v") || "0", 10);
  if (from === to) return;
  el.setAttribute("data-v", to);

  var dur = 420;
  var t0 = performance.now();
  function step(now) {
    var p = Math.min((now - t0) / dur, 1);
    // easing suave al final, para que se frene en vez de cortarse
    var eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * eased).toLocaleString("es");
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function rejectConsent() {
  window.closeApp();
}

function closeApp() {
  window.closeApp();
}

// ---------------------------------------------------------------- eventos

// Punto de entrada que el backend invoca por cada evento del escaneo.
window.onAgentEvent = function (ev) {
  switch (ev.kind) {
    case "collector_start":
      onCollectorStart(ev);
      break;
    case "collector_progress":
      onCollectorProgress(ev);
      break;
    case "collector_done":
      onCollectorDone(ev);
      break;
    case "finding":
      onFinding(ev);
      break;
    case "scan_done":
      onScanDone(ev);
      break;
    case "scan_error":
      onScanError(ev);
      break;
  }
};

function onCollectorStart(ev) {
  document.getElementById("progress-current").textContent = "Analizando " + ev.collector;
  document.getElementById("progress-count").textContent = ev.index + " / " + ev.total;

  var li = state.collectors[ev.collector];
  if (!li) {
    li = document.createElement("li");
    li.innerHTML =
      '<span class="c-icon">◐</span><span class="c-name"></span>' +
      '<span class="c-meta"></span><span class="c-track"><i class="c-fill"></i></span>';
    li.querySelector(".c-name").textContent = ev.collector;
    document.getElementById("collector-list").appendChild(li);
    state.collectors[ev.collector] = li;
  }
  li.className = "running";
  li.querySelector(".c-icon").textContent = "◐";
  li.querySelector(".c-meta").textContent = "";
  li.querySelector(".c-fill").style.width = "0%";

  // La barra global arranca en lo ya completado y avanza dentro del tramo de
  // este colector a medida que llega su avance interno.
  setGlobalProgress(ev.index - 1, ev.total, 0);
}

// onCollectorProgress mueve la barra DENTRO del colector actual. Es lo que
// evita que se vea congelada durante los 30-60 segundos que tarda la MFT.
function onCollectorProgress(ev) {
  var li = state.collectors[ev.collector];
  if (li) {
    var pct = Math.round((ev.fraction || 0) * 100);
    li.querySelector(".c-fill").style.width = pct + "%";
    li.querySelector(".c-meta").textContent = pct + "%";
  }
  setGlobalProgress(ev.index - 1, ev.total, ev.fraction || 0);
}

// setGlobalProgress compone el avance total: colectores terminados más la
// fracción del que está corriendo.
function setGlobalProgress(completed, total, fraction) {
  if (!total) return;
  var pct = ((completed + fraction) / total) * 100;
  document.getElementById("progress-bar").style.width = pct + "%";
  document.getElementById("progress-pct").textContent = Math.round(pct) + "%";
}

function onCollectorDone(ev) {
  var li = state.collectors[ev.collector];
  if (!li) return;

  if (ev.error) {
    li.className = "failed";
    li.querySelector(".c-icon").textContent = "!";
    li.querySelector(".c-meta").textContent = "no disponible";
  } else {
    li.className = "done";
    li.querySelector(".c-icon").textContent = "✓";
    var n = ev.artifacts || 0;
    li.querySelector(".c-meta").textContent = n + (n === 1 ? " artefacto" : " artefactos");
    state.totalArtifacts += n;
  }
  li.querySelector(".c-fill").style.width = "100%";

  setGlobalProgress(ev.index, ev.total, 0);
  countUp(document.getElementById("progress-artifacts-n"), state.totalArtifacts);
}

// onFinding agrega una detección al feed en vivo. La severidad es preliminar:
// el backend todavía no aplicó combos ni deduplicación, así que la pantalla
// final puede mostrar un valor distinto.
function onFinding(ev) {
  var feed = document.getElementById("live-feed");
  var empty = document.getElementById("live-empty");
  if (empty) empty.remove();

  var sev = (ev.severity || "INFO").toUpperCase();
  if (state.live[sev] !== undefined) {
    state.live[sev]++;
    renderCounters(sev);
  }

  var item = document.createElement("div");
  item.className = "live-item lv-" + sev.toLowerCase();
  item.innerHTML =
    '<span class="badge sev-' + sev.toLowerCase() + '"></span>' +
    '<span class="live-title"></span>' +
    '<span class="live-path"></span>';
  item.querySelector(".badge").textContent = sev;
  item.querySelector(".live-title").textContent = ev.title || "";
  // La ruta se muestra en RTL por CSS para que, al recortarse, se vea el
  // nombre del archivo y no el prefijo C:\Windows\... que se repite siempre.
  item.querySelector(".live-path").textContent = ev.path || "";

  feed.insertBefore(item, feed.firstChild);
  state.liveShown++;

  // Podar el final: lo viejo ya se contabilizó en los contadores y va a
  // aparecer completo en la pantalla de resultados.
  while (feed.childNodes.length > MAX_LIVE_NODES) {
    feed.removeChild(feed.lastChild);
  }
}

function renderCounters(bumped) {
  var box = document.getElementById("live-counters");
  var order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  for (var i = 0; i < order.length; i++) {
    var k = order[i];
    var id = "counter-" + k;
    var el = document.getElementById(id);
    if (!el) {
      el = document.createElement("span");
      el.id = id;
      el.className = "counter sev-" + k.toLowerCase();
      box.appendChild(el);
    }
    countUp(el, state.live[k]);
    if (state.live[k] > 0) el.classList.add("on");
    if (k === bumped) {
      el.classList.remove("bump");
      void el.offsetWidth; // reinicia la animación
      el.classList.add("bump");
    }
  }
}

function onScanError(ev) {
  show("screen-results");
  setScanning(false);
  document.getElementById("topbar-status").textContent = "Error";
  var v = document.getElementById("verdict");
  v.className = "verdict level-incompleto";
  document.getElementById("verdict-level").textContent = "ERROR";
  document.getElementById("verdict-summary").textContent =
    "El escaneo no pudo completarse.";
  document.getElementById("verdict-note").textContent = ev.error || "";
}

function onScanDone(ev) {
  show("screen-results");
  setScanning(false);
  document.getElementById("topbar-status").textContent = "Completado";

  var rep = ev.report || {};
  var verdict = rep.verdict || {};
  var findings = rep.findings || [];

  renderVerdict(verdict);
  renderDistribution(findings);
  renderFindings(findings);

  if (rep.reportPath) {
    document.getElementById("report-path").textContent = rep.reportPath;
  }
}

// ---------------------------------------------------------------- render

function renderVerdict(verdict) {
  var level = verdict.level || "LIMPIO";
  var box = document.getElementById("verdict");
  box.className = "verdict level-" + level.toLowerCase();

  var LABEL = {
    LIMPIO: "SIN HALLAZGOS",
    INCOMPLETO: "REVISIÓN PARCIAL",
    SOSPECHOSO: "REQUIERE REVISIÓN",
    EVIDENCIA_FUERTE: "EVIDENCIA FUERTE",
  };
  var lvl = document.getElementById("verdict-level");
  lvl.textContent = LABEL[level] || level;
  // Reinicia la animación por si se vuelve a renderizar.
  lvl.classList.remove("reveal-type");
  void lvl.offsetWidth;
  lvl.classList.add("reveal-type");

  document.getElementById("verdict-summary").textContent = verdict.summary || "";

  var noteEl = document.getElementById("verdict-note");
  if (verdict.failedCollectors && verdict.failedCollectors.length) {
    noteEl.textContent =
      "Revisión parcial: no se pudo leer " +
      verdict.failedCollectors.join(", ") +
      ". Lo que esa fuente hubiera mostrado no está en este resultado.";
    noteEl.hidden = false;
  } else {
    noteEl.hidden = true;
  }
}

// renderDistribution dibuja la proporción real de la evidencia. Un CRITICAL
// entre 300 hallazgos se ve del tamaño que le corresponde, no como titular.
function renderDistribution(findings) {
  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (var i = 0; i < findings.length; i++) {
    var s = findings[i].severity;
    if (counts[s] !== undefined) counts[s]++;
  }

  var order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  var total = findings.length || 1;
  var bar = document.getElementById("dist-bar");
  var legend = document.getElementById("dist-legend");
  bar.innerHTML = "";
  legend.innerHTML = "";

  for (var j = 0; j < order.length; j++) {
    var k = order[j];
    if (!counts[k]) continue;
    var color = "var(--sev-" + k.toLowerCase() + ")";

    var seg = document.createElement("div");
    seg.className = "dist-seg";
    // Arranca en cero y crece: la proporción se "mide" en vez de aparecer ya
    // resuelta. El transition de .dist-seg hace el resto.
    seg.style.width = "0%";
    seg.style.background = color;
    seg.title = counts[k] + " " + k;
    bar.appendChild(seg);
    (function (node, pct) {
      setTimeout(function () { node.style.width = pct + "%"; }, 260);
    })(seg, (counts[k] / total) * 100);

    var item = document.createElement("span");
    item.className = "dist-item";
    item.innerHTML =
      '<span class="dist-swatch" style="background:' + color + '"></span>' +
      '<span class="dist-num"></span><span></span>';
    item.querySelector(".dist-num").textContent = counts[k];
    item.querySelectorAll("span")[2].textContent = k;
    legend.appendChild(item);
  }
}

function renderFindings(findings) {
  var container = document.getElementById("findings");
  if (!findings.length) {
    container.innerHTML = '<div class="empty">No se registraron hallazgos.</div>';
    return;
  }

  // Agrupar por categoría.
  var groups = {};
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    var cat = f.category || "EXECUTION";
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(f);
  }

  // Ordenar categorías por su hallazgo más grave.
  var cats = Object.keys(groups);
  cats.sort(function (a, b) {
    return maxSeverity(groups[b]) - maxSeverity(groups[a]);
  });

  container.innerHTML = "";
  for (var c = 0; c < cats.length; c++) {
    var g = buildGroup(cats[c], groups[cats[c]]);
    // Escalonado: los grupos entran de a uno, el más grave primero.
    g.style.animationDelay = (0.28 + c * 0.09).toFixed(2) + "s";
    container.appendChild(g);
  }
}

function maxSeverity(list) {
  var m = 0;
  for (var i = 0; i < list.length; i++) {
    var v = SEV_ORDER[list[i].severity] || 0;
    if (v > m) m = v;
  }
  return m;
}

function buildGroup(category, items) {
  items.sort(function (a, b) {
    return (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0);
  });

  var group = document.createElement("div");
  group.className = "group";
  // Las categorías que solo tienen INFO arrancan colapsadas: son ruido para
  // quien mira el resultado, pero siguen disponibles.
  if (maxSeverity(items) > SEV_ORDER.INFO) group.classList.add("open");

  var head = document.createElement("div");
  head.className = "group-head";
  head.innerHTML =
    '<span class="group-caret">▶</span>' +
    '<span class="group-title"></span>' +
    '<span class="group-count"></span>';
  head.querySelector(".group-title").textContent = CATEGORY_LABEL[category] || category;
  head.querySelector(".group-count").textContent =
    items.length + (items.length === 1 ? " hallazgo" : " hallazgos");
  head.onclick = function () {
    group.classList.toggle("open");
  };

  var body = document.createElement("div");
  body.className = "group-body";
  for (var i = 0; i < items.length; i++) {
    body.appendChild(buildFinding(items[i]));
  }

  group.appendChild(head);
  group.appendChild(body);
  return group;
}

// revealable reproduce del lado del cliente la misma regla que ui.RevealablePath:
// solo las rutas reales del disco reciben botón de carpeta. Una tarea
// programada o un nombre de servicio no tienen ubicación que abrir.
function revealable(path) {
  if (!path) return false;
  if (path.indexOf("<sin-resolver>") !== -1) return false;
  if (/^[A-Za-z]:[\\/]/.test(path)) return true;
  return path.indexOf("\\\\") === 0;
}

function buildFinding(f) {
  var el = document.createElement("div");
  el.className = "finding";

  var sev = (f.severity || "INFO").toLowerCase();
  el.innerHTML =
    '<span class="badge sev-' + sev + '"></span>' +
    '<div class="finding-main">' +
    '<div class="finding-title"></div>' +
    '<div class="finding-path"></div>' +
    "</div>";

  el.querySelector(".badge").textContent = f.severity || "INFO";
  el.querySelector(".finding-title").textContent = f.title || "";
  el.querySelector(".finding-path").textContent = f.artifact || "";

  if (revealable(f.artifact)) {
    var btn = document.createElement("button");
    btn.className = "reveal";
    btn.textContent = "\u{1F5C1}";
    btn.title = "Abrir la ubicación en el explorador";
    btn.setAttribute("aria-label", "Abrir la ubicación de " + (f.artifact || ""));
    btn.onclick = function () {
      // El backend valida de nuevo: el archivo puede haber sido borrado, en
      // cuyo caso abre el directorio que lo contenía.
      window.revealPath(f.artifact).then(function (ok) {
        if (!ok) {
          btn.title = "La ubicación ya no existe";
          return;
        }
        btn.classList.add("done");
      });
    };
    el.appendChild(btn);
  }
  return el;
}
