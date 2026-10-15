// Виртуальный hex-viewer для больших потоков (ТЗ §16.1).
// Рендерит только видимые строки, подгружает байты чанками через API.
(function () {
  const BYTES_PER_LINE = 16;
  const LINE_HEIGHT = 17;       // должно совпадать с CSS (.hex-line { height:17px })
  const OVERSCAN = 20;          // рендерим с запасом сверху/снизу
  const CHUNK_BYTES = 64 * 1024; // 64 КиБ = 4096 строк

  class HexViewer {
    /**
     * @param {HTMLElement} container — корневой div
     * @param {Object} opts
     * @param {string} opts.sessionId
     * @param {string} opts.direction
     * @param {string} opts.projectId
     * @param {number} opts.size
     * @param {Array}  opts.marks      — [{start, end, kind: 'gap'|'amb'|'msg-N'}]
     * @param {Function} [opts.onByteClick]
     */
    constructor(container, opts) {
      this.root = container;
      this.sessionId = opts.sessionId;
      this.direction = opts.direction;
      this.projectId = opts.projectId;
      this.size = opts.size || 0;
      this.marks = opts.marks || [];
      this.onByteClick = opts.onByteClick || null;

      this.chunks = new Map();
      this.pending = new Set();
      this.firstRendered = -1;
      this.lastRendered = -1;
      this.flashOffset = null;
      this._flashRange = null;
      this._flashTimer = null;
      this._selectedOffsets = null;   // Set<string> текущего выделения

      this.root.classList.add("hex-vscroll");
      this.root.style.height = "600px";
      this.root.style.overflowY = "auto";
      this.root.style.position = "relative";

      this.root.innerHTML =
        '<div class="hex-spacer"></div>' +
        '<div class="hex-window"></div>';
      this.spacer = this.root.querySelector(".hex-spacer");
      this.windowEl = this.root.querySelector(".hex-window");

      const totalLines = Math.max(1, Math.ceil(this.size / BYTES_PER_LINE));
      this.spacer.style.height = (totalLines * LINE_HEIGHT) + "px";

      this.windowEl.style.position = "absolute";
      this.windowEl.style.left = "0";
      this.windowEl.style.right = "0";
      this.windowEl.style.top = "0";
      this.windowEl.style.willChange = "transform";

      this.root.addEventListener("scroll", () => this.onScroll());

      // Синхронизация выделения hex ↔ ASCII.
      this._onSelectionChange = () => this.updateSelectionFromDom();
      document.addEventListener("selectionchange", this._onSelectionChange);

      this.onScroll();
    }

    get lineHeight() { return LINE_HEIGHT; }

    visibleRange() {
      const scrollTop = this.root.scrollTop;
      const viewport = this.root.clientHeight || 600;
      const first = Math.max(0, Math.floor(scrollTop / LINE_HEIGHT) - OVERSCAN);
      const visible = Math.ceil(viewport / LINE_HEIGHT) + 2 * OVERSCAN;
      const last = first + visible;
      return [first, last];
    }

    onScroll() {
      const [first, last] = this.visibleRange();
      if (first === this.firstRendered && last === this.lastRendered) return;
      this.firstRendered = first;
      this.lastRendered = last;
      this.render();
      this.ensureChunks(first, last);
    }

    async ensureChunks(firstLine, lastLine) {
      const firstByte = firstLine * BYTES_PER_LINE;
      const lastByte = Math.min(this.size, (lastLine + 1) * BYTES_PER_LINE);
      const firstChunk = Math.floor(firstByte / CHUNK_BYTES);
      const lastChunk = Math.floor(Math.max(0, lastByte - 1) / CHUNK_BYTES);
      const tasks = [];
      for (let c = firstChunk; c <= lastChunk; c++) {
        if (this.chunks.has(c) || this.pending.has(c)) continue;
        this.pending.add(c);
        tasks.push(this.loadChunk(c));
      }
      if (tasks.length) {
        await Promise.all(tasks);
        this.render();
      }
    }

    async loadChunk(chunkIdx) {
      const offset = chunkIdx * CHUNK_BYTES;
      const length = Math.min(CHUNK_BYTES, this.size - offset);
      if (length <= 0) { this.pending.delete(chunkIdx); return; }
      try {
        const r = await fetch(
          "/api/sessions/" + this.sessionId + "/stream/" + this.direction +
          "/bytes?project_id=" + encodeURIComponent(this.projectId) +
          "&offset=" + offset + "&length=" + length
        );
        if (!r.ok) throw new Error("HTTP " + r.status);
        const buf = new Uint8Array(await r.arrayBuffer());
        this.chunks.set(chunkIdx, buf);
      } catch (e) {
        this.chunks.set(chunkIdx, null);
      } finally {
        this.pending.delete(chunkIdx);
      }
    }

    byteAt(absOffset) {
      if (absOffset < 0 || absOffset >= this.size) return null;
      const chunkIdx = Math.floor(absOffset / CHUNK_BYTES);
      const chunk = this.chunks.get(chunkIdx);
      if (!chunk) return undefined;
      if (chunk === null) return null;
      const local = absOffset - chunkIdx * CHUNK_BYTES;
      return local < chunk.length ? chunk[local] : null;
    }

    markAt(offset) {
      for (const m of this.marks) {
        if (offset >= m.start && offset < m.end) return m.kind;
      }
      return null;
    }

    render() {
      const [first, last] = [this.firstRendered, this.lastRendered];
      if (first < 0) return;
      const totalLines = Math.ceil(this.size / BYTES_PER_LINE) || 1;
      const linesHtml = [];
      for (let line = first; line < last && line < totalLines; line++) {
        const off = line * BYTES_PER_LINE;
        const offHex = off.toString(16).padStart(8, "0");

        let hexPart = "";
        let asciiPart = "";
        for (let i = 0; i < BYTES_PER_LINE; i++) {
          const abs = off + i;
          if (abs >= this.size) {
            hexPart += "   ";
            asciiPart += " ";
            continue;
          }
          const b = this.byteAt(abs);
          if (b === undefined) {
            hexPart += '<span class="byte pending" data-off="' + abs + '">??</span> ';
            asciiPart += '<span class="byte pending ascii-byte" data-off="' +
                         abs + '">?</span>';
          } else if (b === null) {
            hexPart += '<span class="byte gap" data-off="' + abs + '">..</span> ';
            asciiPart += '<span class="byte gap ascii-byte" data-off="' +
                         abs + '">·</span>';
          } else {
            const h = b.toString(16).padStart(2, "0");
            const kind = this.markAt(abs);
            const classes = ["byte"];
            if (kind) classes.push(kind);
            if (this.flashOffset === abs) classes.push("flash");
            if (this._flashRange &&
                abs >= this._flashRange[0] && abs < this._flashRange[1]) {
              classes.push("flash-range");
            }
            const cls = classes.join(" ");
            hexPart += '<span class="' + cls + '" data-off="' + abs + '">' + h + "</span> ";
            const ch = b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
            asciiPart += '<span class="' + cls + ' ascii-byte" data-off="' +
                         abs + '">' + window.taptuna.escapeHtml(ch) + "</span>";
          }
        }
        linesHtml.push(
          '<div class="hex-line">' +
            '<span class="off">' + offHex + "</span>  " +
            hexPart +
            ' <span class="ascii">|' + asciiPart + "|</span>" +
          "</div>"
        );
      }
      this.windowEl.innerHTML = linesHtml.join("");
      this.windowEl.style.transform = "translateY(" + (first * LINE_HEIGHT) + "px)";

      // Восстановить выделение после перерисовки (при скролле).
      if (this._selectedOffsets && this._selectedOffsets.size) {
        const set = this._selectedOffsets;
        this.windowEl.querySelectorAll(".byte[data-off]").forEach((el) => {
          if (set.has(el.dataset.off)) el.classList.add("selected");
        });
      }

      if (this.onByteClick) {
        this.windowEl.querySelectorAll(".byte[data-off]").forEach((el) => {
          el.addEventListener("click", () => {
            // Не открывать popup, если есть активное выделение —
            // пользователь тянул мышь, а не кликал.
            const sel = window.getSelection();
            if (sel && !sel.isCollapsed) return;
            this.onByteClick(parseInt(el.dataset.off, 10), el);
          });
        });
      }
    }

    // ============================================================
    // Синхронизация выделения: hex ↔ ASCII
    // ============================================================
    updateSelectionFromDom() {
      const sel = window.getSelection();
      if (!sel || sel.isCollapsed || sel.rangeCount === 0) {
        this.clearSelectionHighlight();
        return;
      }
      const range = sel.getRangeAt(0);
      // Проверяем, попадает ли выделение в наш root.
      const inRoot =
        this.root.contains(range.commonAncestorContainer) ||
        this.root.contains(range.startContainer) ||
        this.root.contains(range.endContainer);
      if (!inRoot) {
        this.clearSelectionHighlight();
        return;
      }

      const offsets = new Set();
      this.windowEl.querySelectorAll(".byte[data-off]").forEach((el) => {
        if (range.intersectsNode(el)) {
          offsets.add(el.dataset.off);
        }
      });
      this.applySelectionHighlight(offsets);
    }

    applySelectionHighlight(offsets) {
      this._selectedOffsets = offsets;
      const bytes = this.windowEl.querySelectorAll(".byte[data-off]");
      bytes.forEach((el) => {
        if (offsets.has(el.dataset.off)) {
          el.classList.add("selected");
        } else {
          el.classList.remove("selected");
        }
      });
    }

    clearSelectionHighlight() {
      if (this._selectedOffsets === null) return;
      this._selectedOffsets = null;
      this.windowEl.querySelectorAll(".byte.selected").forEach((el) => {
        el.classList.remove("selected");
      });
    }

    /** Прокрутка к offset с визуальной подсветкой одного байта. */
    jumpTo(absOffset) {
      if (absOffset < 0) absOffset = 0;
      if (absOffset >= this.size && this.size > 0) absOffset = this.size - 1;

      const line = Math.floor(absOffset / BYTES_PER_LINE);
      const viewportLines = Math.floor((this.root.clientHeight || 600) / LINE_HEIGHT);
      const targetScroll = Math.max(0, (line - Math.floor(viewportLines / 2)) * LINE_HEIGHT);
      this.root.scrollTop = targetScroll;

      this.firstRendered = -1;
      this.lastRendered = -1;
      this.onScroll();

      this.flashOffset = absOffset;
      this._flashRange = null;
      this.render();
      clearTimeout(this._flashTimer);
      this._flashTimer = setTimeout(() => {
        this.flashOffset = null;
        this.render();
      }, 2000);

      this.ensureChunks(line, line + viewportLines);
    }

    /** Подсветить диапазон байт [start, end) на 2.5 секунды. */
    flashRange(start, end) {
      if (start < 0) start = 0;
      if (end > this.size) end = this.size;
      if (end <= start) return;

      const line = Math.floor(start / BYTES_PER_LINE);
      const viewportLines = Math.floor((this.root.clientHeight || 600) / LINE_HEIGHT);
      const targetScroll = Math.max(0, (line - Math.floor(viewportLines / 2)) * LINE_HEIGHT);
      this.root.scrollTop = targetScroll;

      this.firstRendered = -1;
      this.lastRendered = -1;
      this.onScroll();

      this.flashOffset = null;
      this._flashRange = [start, end];
      this.render();
      clearTimeout(this._flashTimer);
      this._flashTimer = setTimeout(() => {
        this._flashRange = null;
        this.render();
      }, 2500);

      const lastLine = Math.floor((end - 1) / BYTES_PER_LINE);
      this.ensureChunks(line, lastLine);
    }

    /** Обновление marks без перезагрузки. */
    setMarks(marks) {
      this.marks = marks || [];
      this.firstRendered = -1;
      this.onScroll();
    }

    /** Освобождение ресурсов. */
    destroy() {
      document.removeEventListener("selectionchange", this._onSelectionChange);
    }
  }

  window.taptuna = window.taptuna || {};
  window.taptuna.HexViewer = HexViewer;
})();