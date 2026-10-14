// Общие утилиты: fetch-хелперы, toast, форматирование.
(function () {
  window.taptuna = window.taptuna || {};

  window.taptuna.api = async function (method, url, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(url, opts);
    let data = null;
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      data = await r.json();
    } else {
      data = await r.text();
    }
    if (!r.ok) {
      const err = (data && data.error) || { message: String(data) };
      throw Object.assign(new Error(err.message || "HTTP " + r.status), { payload: err, status: r.status });
    }
    return data;
  };

  window.taptuna.toast = function (message, kind) {
    const root = document.getElementById("toast-root");
    if (!root) return;
    const el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    el.textContent = message;
    root.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  };

  window.taptuna.escapeHtml = function (s) {
    if (s == null) return "";
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[c]);
  };

  window.taptuna.bytesToHex = function (bytes) {
    if (!bytes) return "";
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  window.taptuna.formatBytes = function (n) {
    if (n == null) return "";
    const units = ["B", "KiB", "MiB", "GiB"];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(i === 0 ? 0 : 1) + " " + units[i];
  };

  window.taptuna.formatTime = function (epochSec) {
    if (epochSec == null) return "";
    return new Date(epochSec * 1000).toISOString().replace("T", " ").slice(0, 19);
  };

  // Рендер hex-дампа в элемент .hex
  window.taptuna.renderHex = function (el, bytes, options) {
    options = options || {};
    const marks = options.marks || [];  // [{start, end, kind: "gap"|"amb"}]
    const perLine = 16;
    const lines = [];
    const markAt = (i) => {
      for (const m of marks) {
        if (i >= m.start && i < m.end) return m.kind;
      }
      return null;
    };
    for (let off = 0; off < bytes.length; off += perLine) {
      const chunk = bytes.slice(off, off + perLine);
      let hexPart = "";
      let asciiPart = "";
      for (let i = 0; i < chunk.length; i++) {
        const b = chunk[i];
        const h = b.toString(16).padStart(2, "0");
        const kind = markAt(off + i);
        const cls = "byte" + (kind ? " " + kind : "");
        hexPart += '<span class="' + cls + '">' + h + "</span> ";
        const ch = b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
        asciiPart += window.taptuna.escapeHtml(ch);
      }
      const pad = (perLine - chunk.length) * 3;
      const offHex = off.toString(16).padStart(8, "0");
      lines.push(
        '<span class="off">' + offHex + "</span>  " +
        hexPart + " ".repeat(pad) + " |" + asciiPart + "|"
      );
    }
    el.innerHTML = lines.join("\n");
  };
})();