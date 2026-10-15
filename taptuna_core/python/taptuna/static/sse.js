(function () {
  const jobs = new Map();   // job_id -> {state, kind, fraction, message, finished}
  const panel = document.getElementById("jobs-panel");
  const list = document.getElementById("jobs-list");
  const HIDDEN_KEY = "taptuna_jobs_panel_hidden";

  // Скрывать/показывать панель
  function setPanelVisible(v) {
    if (!panel) return;
    panel.hidden = !v;
    try { localStorage.setItem(HIDDEN_KEY, v ? "0" : "1"); } catch (e) {}
  }
  function isPanelHidden() {
    try { return localStorage.getItem(HIDDEN_KEY) === "1"; } catch (e) { return false; }
  }

  function ensurePanel() {
    if (!panel || !list) return;
    if (isPanelHidden()) setPanelVisible(true);
  }

  function updateToggleButton() {
    let btn = document.getElementById("jobs-toggle");
    if (!btn) {
      btn = document.createElement("button");
      btn.id = "jobs-toggle";
      btn.type = "button";
      btn.style.cssText =
        "position:fixed; bottom:1rem; right:1rem; z-index:210;" +
        "padding:0.5rem 0.9rem; background:#2b6cb0; color:#fff;" +
        "border:none; border-radius:6px; cursor:pointer; font:inherit;" +
        "box-shadow:0 2px 8px rgba(0,0,0,0.15); display:none;";
      btn.textContent = "Задачи";
      btn.addEventListener("click", () => setPanelVisible(true));
      document.body.appendChild(btn);
    }
    const active = jobs.size;
    if (!panel.hidden) {
      btn.style.display = "none";
    } else {
      btn.style.display = active > 0 ? "block" : "none";
      btn.textContent = "Задачи (" + active + ")";
    }
  }

  function renderJob(jobId) {
    if (!list) return;
    const entry = jobs.get(jobId);
    if (!entry) return;
    let el = document.getElementById("job-" + jobId);
    if (!el) {
      el = document.createElement("div");
      el.className = "job-item";
      el.id = "job-" + jobId;
      list.prepend(el);
    }
    const state = entry.state || "pending";
    const kind = entry.kind || "job";
    const msg = entry.message || "";
    const frac = entry.fraction != null ? entry.fraction : 0;
    el.innerHTML =
      '<div class="job-head">' +
        '<span class="job-kind">' + kind + '</span>' +
        '<span class="job-state">' + state + '</span>' +
      '</div>' +
      '<div class="job-msg">' + msg + '</div>' +
      '<div class="bar"><div style="width:' + Math.round(frac * 100) + '%"></div></div>';
  }

  function renderAll() {
    if (!list) return;
    list.innerHTML = "";
    for (const jobId of jobs.keys()) renderJob(jobId);
    updateToggleButton();
  }

  function clearFinished() {
    // Удаляем завершённые из клиента
    for (const [jobId, j] of Array.from(jobs.entries())) {
      if (j.finished) {
        jobs.delete(jobId);
        const el = document.getElementById("job-" + jobId);
        if (el) el.remove();
      }
    }
    updateToggleButton();
    // И с сервера
    fetch("/api/jobs/clear", { method: "POST" }).catch(() => {});
  }

  function ensureHeaderButtons() {
    if (!panel) return;
    const header = panel.querySelector("header");
    if (!header) return;
    if (header.querySelector("#jobs-clear")) return;

    const clearBtn = document.createElement("button");
    clearBtn.id = "jobs-clear";
    clearBtn.type = "button";
    clearBtn.textContent = "Очистить";
    clearBtn.style.cssText = "font-size:0.85rem; margin-right:0.4rem;";
    clearBtn.addEventListener("click", clearFinished);

    const closeBtn = header.querySelector("#jobs-close");
    header.insertBefore(clearBtn, closeBtn);
  }

  function subscribe(jobId, kind) {
    const es = new EventSource("/api/jobs/" + jobId + "/events");
    jobs.set(jobId, { state: "running", kind: kind || "job",
                      fraction: 0, message: "", finished: false });
    ensurePanel();
    ensureHeaderButtons();
    renderJob(jobId);
    updateToggleButton();

    es.addEventListener("progress", (e) => {
      const d = JSON.parse(e.data);
      const j = jobs.get(jobId) || {};
      j.message = d.message || "";
      j.fraction = d.fraction != null ? d.fraction : j.fraction;
      jobs.set(jobId, j);
      renderJob(jobId);
    });
    es.addEventListener("log", (e) => {
      const d = JSON.parse(e.data);
      const j = jobs.get(jobId) || {};
      j.message = d.message || "";
      jobs.set(jobId, j);
      renderJob(jobId);
    });
    es.addEventListener("result", (e) => {
      const d = JSON.parse(e.data);
      document.dispatchEvent(new CustomEvent("job:result",
        { detail: { jobId: jobId, result: d.result } }));
    });
    es.addEventListener("done", () => {
      const j = jobs.get(jobId) || {};
      j.state = "completed";
      j.fraction = 1;
      j.finished = true;
      jobs.set(jobId, j);
      renderJob(jobId);
      updateToggleButton();
      document.dispatchEvent(new CustomEvent("job:done", { detail: { jobId: jobId } }));
      es.close();
      // Автоочистка через 5 секунд
      setTimeout(() => {
        const jj = jobs.get(jobId);
        if (jj && jj.finished) {
          jobs.delete(jobId);
          const el = document.getElementById("job-" + jobId);
          if (el) el.remove();
          updateToggleButton();
        }
      }, 5000);
    });
    es.addEventListener("close", () => es.close());
    es.onerror = () => es.close();
    return jobId;
  }

  document.addEventListener("click", (e) => {
    if (e.target && e.target.id === "jobs-close" && panel) {
      setPanelVisible(false);
    }
  });

  // На старте: если не скрыта пользователем и есть активные — показать
  if (panel && !isPanelHidden()) {
    ensureHeaderButtons();
  }
  updateToggleButton();

  window.taptuna = window.taptuna || {};
  window.taptuna.subscribeJob = subscribe;
  window.taptuna.clearJobs = clearFinished;
})();