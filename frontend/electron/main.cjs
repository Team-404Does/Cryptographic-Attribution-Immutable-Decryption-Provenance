// Electron shell: starts the local FastAPI backend (loopback only) and shows the UI.
// No remote content is ever loaded; all navigation off 127.0.0.1 is blocked.
const { app, BrowserWindow, shell, session } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const http = require("http");

const PORT = 8765;
const ROOT = path.resolve(__dirname, "..", "..");
const BACKEND_DIR = path.join(ROOT, "backend");
const UI_URL = process.env.SIH_UI_URL || `http://127.0.0.1:${PORT}/`;
let backend = null;

function pythonPath() {
  if (process.env.SIH_PYTHON) return process.env.SIH_PYTHON;
  const venv = process.platform === "win32"
    ? path.join(ROOT, ".venv", "Scripts", "python.exe")
    : path.join(ROOT, ".venv", "bin", "python");
  return fs.existsSync(venv) ? venv : "python3";
}

function ping() {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port: PORT, path: "/api/status", timeout: 1500 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => { req.destroy(); resolve(false); });
  });
}

async function startBackend() {
  if (await ping()) return; // already running (e.g. started manually)
  backend = spawn(pythonPath(), ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(PORT)], {
    cwd: BACKEND_DIR,
    stdio: "inherit",
  });
  backend.on("exit", (code) => { if (code) console.error(`backend exited with code ${code}`); backend = null; });
  for (let i = 0; i < 120; i++) {
    if (await ping()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("backend did not start within 60 s");
}

// SIH_SMOKE=<file.png>: headless smoke test - load the UI in a hidden window, save a capture, quit.
const SMOKE = process.env.SIH_SMOKE;

function createWindow() {
  const win = new BrowserWindow({
    show: !SMOKE,
    width: 1440,
    height: 920,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: "#070b12",
    title: "Leak Attribution Console",
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.removeMenu();
  const allowed = (url) => url.startsWith(`http://127.0.0.1:${PORT}`) || url.startsWith(UI_URL);
  win.webContents.on("will-navigate", (e, url) => { if (!allowed(url)) e.preventDefault(); });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (allowed(url)) {
      shell.openExternal(url); // evidence PDFs open in the system viewer
    }
    return { action: "deny" };
  });
  win.loadURL(UI_URL);
  if (SMOKE) {
    win.webContents.on("console-message", (_e, level, msg) => { if (level >= 2) console.error("renderer:", msg); });
    win.webContents.once("did-finish-load", () => setTimeout(async () => {
      const title = await win.webContents.executeJavaScript("document.body.innerText.slice(0, 200)");
      console.log("smoke: page text:", JSON.stringify(title));
      fs.writeFileSync(SMOKE, (await win.webContents.capturePage()).toPNG());
      console.log("smoke: capture written to", SMOKE);
      app.quit();
    }, 2500));
  }
}

app.whenReady().then(async () => {
  // Air-gap guard: refuse every request that is not to the local backend / dev server.
  session.defaultSession.webRequest.onBeforeRequest((details, cb) => {
    const u = details.url;
    const local = /^(https?|wss?):\/\/(127\.0\.0\.1|localhost)(:\d+)?\//.test(u) || u.startsWith("devtools:") ||
      u.startsWith("blob:") || u.startsWith("data:");
    cb({ cancel: !local });
  });
  try {
    await startBackend();
  } catch (e) {
    console.error(e);
  }
  createWindow();
});

app.on("window-all-closed", () => app.quit());
app.on("will-quit", () => { if (backend) backend.kill(); });
