const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const candidates = process.platform === "win32"
  ? [path.join(root, ".venv", "Scripts", "python.exe"), "python"]
  : [path.join(root, ".venv", "bin", "python"), "python3", "python"];

const python = candidates.find((candidate) => candidate === "python" || candidate === "python3" || fs.existsSync(candidate));
const args = ["-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8765", ...process.argv.slice(2)];

const child = spawn(python, args, {
  cwd: root,
  stdio: "inherit",
  windowsHide: true
});

child.on("exit", (code) => process.exit(code ?? 0));
