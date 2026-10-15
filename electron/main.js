/**
 * Electron main process для TapTuna.
 *
 * 1. Находит свободный порт.
 * 2. Запускает `taptuna-server` (из resourcesPath в проде, из ../taptuna_core/dist в дев).
 * 3. Ждёт GET /api/projects → 200.
 * 4. Открывает окно с /welcome.
 * 5. При закрытии окна — убивает child.
 */
const { app, BrowserWindow, dialog, shell } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const net = require("net");
const http = require("http");
const os = require("os");

let mainWindow = null;
let serverProc = null;
let serverPort = null;

const isDev = process.env.TAPTUNA_DEV === "1";

// Где искать бинарь сервера
function findServerBinary() {
  const candidates = [];
  if (app.isPackaged) {
    candidates.push(path.join(process.resourcesPath, "taptuna-server"));
  } else {
    // Dev-режим: бинарь должен быть собран через PyInstaller
    candidates.push(path.join(__dirname, "bin", "taptuna-server"));
    candidates.push(
      path.join(__dirname, "..", "taptuna_core", "dist", "taptuna-server")
    );
  }
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

// Находит свободный порт начиная с 5000
function findFreePort(start = 5000) {
  return new Promise((resolve, reject) => {
    const tryPort = (port) => {
      const srv = net.createServer();
      srv.once("error", (e) => {
        if (e.code === "EADDRINUSE") {
          tryPort(port + 1);
        } else {
          reject(e);
        }
      });
      srv.once("listening", () => {
        srv.close(() => resolve(port));
      });
      srv.listen(port, "127.0.0.1");
    };
    tryPort(start);
  });
}

// Ждёт, пока сервер ответит на /api/projects
function waitForServer(port, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const tryOnce = () => {
      const req = http.get(
        { host: "127.0.0.1", port, path: "/api/projects", timeout: 1500 },
        (res) => {
          res.resume();
          if (res.statusCode === 200) return resolve();
          retry();
        }
      );
      req.on("error", retry);
      req.on("timeout", () => { req.destroy(); retry(); });
    };
    const retry = () => {
      if (Date.now() > deadline) {
        return reject(new Error("Сервер не ответил за " + timeoutMs + " мс"));
      }
      setTimeout(tryOnce, 300);
    };
    tryOnce();
  });
}

function startServer(binary, port) {
  // Логи: ~/TapTuna/logs/server.log (сам сервер тоже туда пишет)
  const home = path.join(os.homedir(), "TapTuna");
  fs.mkdirSync(path.join(home, "logs"), { recursive: true });
  const logPath = path.join(home, "logs", "electron-server.log");
  const logStream = fs.createWriteStream(logPath, { flags: "a" });

  const proc = spawn(binary, ["--port", String(port)], {
    cwd: home,
    env: {
      ...process.env,
      TAPTUNA_HOME: home,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  proc.stdout.pipe(logStream);
  proc.stderr.pipe(logStream);

  proc.on("exit", (code, signal) => {
    if (mainWindow && !mainWindow.isDestroyed() && code !== 0 && code !== null) {
      dialog.showErrorBox(
        "Сервер остановился",
        `Код выхода: ${code}\nЛоги: ${logPath}`
      );
    }
  });

  return proc;
}

function createWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    title: "TapTuna — Protocol Laboratory",
    backgroundColor: "#ffffff",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadURL(`http://127.0.0.1:${port}/welcome`);

  // В dev — открыть devtools
  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  // Внешние ссылки — открывать в браузере, не в окне
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!url.startsWith(`http://127.0.0.1:${port}`)) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  mainWindow.on("closed", () => { mainWindow = null; });
}

async function bootstrap() {
  const binary = findServerBinary();
  if (!binary) {
    dialog.showErrorBox(
      "Не найден серверный бинарь",
      "taptuna-server не найден. Проверьте установку приложения."
    );
    app.quit();
    return;
  }

  try {
    serverPort = await findFreePort(5000);
    serverProc = startServer(binary, serverPort);
    await waitForServer(serverPort, 15000);
    createWindow(serverPort);
  } catch (e) {
    dialog.showErrorBox(
      "Ошибка запуска",
      String(e && e.message ? e.message : e)
    );
    app.quit();
  }
}

app.whenReady().then(bootstrap);

app.on("window-all-closed", () => {
  if (serverProc && !serverProc.killed) {
    serverProc.kill("SIGTERM");
    setTimeout(() => {
      if (serverProc && !serverProc.killed) serverProc.kill("SIGKILL");
    }, 3000);
  }
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  if (serverProc && !serverProc.killed) serverProc.kill("SIGTERM");
});