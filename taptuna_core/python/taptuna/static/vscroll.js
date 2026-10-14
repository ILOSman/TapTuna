// Виртуальный hex-viewer для больших потоков (ТЗ §16.1).
// Рендерит только видимые строки, подгружает байты чанками через API.
(function () {
  const BYTES_PER_LINE = 16;
  const LINE_HEIGHT = 17;       // должно совпадать с CSS (.hex-line { height:17px })
  const OVERSCAN = 20;          // рендерим с запасом сверху/снизу
  const CHUNK_BYTES = 64 * 1024; // 64 КиБ = 4096 строк

  class HexViewer {
    /**
     * @param {HTMLElement} container — корневой div (позиционирование absolute)
     * @param {Object} opts
     * @param {string} opts.sessionId
     * @param {string} opts.direction  — 'a_to_b' | 'b_to_a'
     * @param {string} opts.projectId
     * @param {number} opts.size       — общее число байт в потоке
     * @param {Array}  opts.marks      — [{start, end, kind: 'gap'|'amb'}]
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

      this.chunks = new Map();    // chunkIdx -> Uint8Array
      this.pending = new Set();   // chunkIdx, которые сейчас грузятся
      this.firstRendered = -1;
      this.lastRendered = -1;

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
        // Помечаем чанк как недоступный — рендер покажет ".."
        this.chunks.set(chunkIdx, null);
      } finally {
        this.pending.delete(chunkIdx);
      }
    }

    byteAt(absOffset) {
      if (absOffset < 0 || absOffset >= this.size) return null;
      const chunkIdx = Math.floor(absOffset / CHUNK_BYTES);
      const chunk = this.chunks.get(chunkIdx);
      if (!chunk) return undefined;   // ещё не загружен
      if (chunk === null) return null; // недоступен
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
            hexPart += '<span class="byte pending">??</span> ';
            asciiPart += "?";
          } else if (b === null) {
            hexPart += '<span class="byte gap">..</span> ';
            asciiPart += "·";
          } else {
            const h = b.toString(16).padStart(2, "0");
            const kind = this.markAt(abs);
            const classes = ["byte"];
            if (kind) classes.push(kind);
            if (this.flashOffset === abs) classes.push("flash");
            const cls = classes.join(" ");
            hexPart += '<span class="' + cls + '" data-off="' + abs + '">' + h + "</span> ";
            const ch = b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
            asciiPart += window.taptuna.escapeHtml(ch);
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
      // Сдвигаем окно к первой видимой строке
      this.windowEl.style.transform = "translateY(" + (first * LINE_HEIGHT) + "px)";

      if (this.onByteClick) {
        this.windowEl.querySelectorAll(".byte[data-off]").forEach((el) => {
          el.addEventListener("click", () => {
            this.onByteClick(parseInt(el.dataset.off, 10), el);
          });
        });
      }
    }

    /** Прокрутка к offset (для jump-to-offset). */
    /** Прокрутка к offset с визуальной подсветкой байта. */
    jumpTo(absOffset) {
      if (absOffset < 0) absOffset = 0;
      if (absOffset >= this.size && this.size > 0) absOffset = this.size - 1;

      // Прокручиваем так, чтобы целевая строка была в середине окна
      const line = Math.floor(absOffset / BYTES_PER_LINE);
      const viewportLines = Math.floor((this.root.clientHeight || 600) / LINE_HEIGHT);
      const targetScroll = Math.max(0, (line - Math.floor(viewportLines / 2)) * LINE_HEIGHT);
      this.root.scrollTop = targetScroll;

      // Событие scroll может прийти асинхронно; синхронизируем состояние вручную.
      this.firstRendered = -1;
      this.lastRendered = -1;
      this.onScroll();

      // Визуальная подсветка целевого байта — снимаем старую, ставим новую.
      this.flashOffset = absOffset;
      this.render();
      clearTimeout(this._flashTimer);
      this._flashTimer = setTimeout(() => {
        this.flashOffset = null;
        this.render();
      }, 2000);

      // Подгружаем чанк, если его ещё нет.
      this.ensureChunks(line, line + viewportLines);
    }

    /** Обновление marks без перезагрузки. */
    setMarks(marks) {
      this.marks = marks || [];
      this.firstRendered = -1;
      this.onScroll();
    }
  }

  window.taptuna = window.taptuna || {};
  window.taptuna.HexViewer = HexViewer;
})();