// SSE-подписка на job + управление панелью задач (§15).
(function () {
  const jobs = new Map();  // job_id -> { state, data, eventSource }
  const panel = document.getElementById("jobs-panel");
  const list = document.getElementById("jobs-list");

  function ensurePanel() {
    if (!panel || !list) return;
    panel.hidden = false;
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

  function subscribe(jobId, kind) {
    const es = new EventSource("/api/jobs/" + jobId + "/events");
    jobs.set(jobId, { state: "running", kind, fraction: 0, message: "" });
    ensurePanel();
    renderJob(jobId);

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
      const j = jobs.get(jobId) || {};
      j.result = d.result;
      jobs.set(jobId, j);
      document.dispatchEvent(new CustomEvent("job:result", { detail: { jobId, result: d.result } }));
    });

    es.addEventListener("error", (e) => {
      try {
        const d = JSON.parse(e.data);
        window.taptuna.toast("Ошибка: " + (d.error && d.error.message || "unknown"), "err");
      } catch (_) {}
    });

    es.addEventListener("done", () => {
      const j = jobs.get(jobId) || {};
      j.state = "completed";
      j.fraction = 1;
      jobs.set(jobId, j);
      renderJob(jobId);
      document.dispatchEvent(new CustomEvent("job:done", { detail: { jobId } }));
      es.close();
    });

    es.addEventListener("close", () => es.close());
    es.onerror = () => { es.close(); };

    return jobId;
  }

  document.addEventListener("click", (e) => {
    if (e.target && e.target.id === "jobs-close" && panel) {
      panel.hidden = true;
    }
  });

  window.taptuna = window.taptuna || {};
  window.taptuna.subscribeJob = subscribe;
  window.taptuna.listJobs = () => Array.from(jobs.entries());
})();