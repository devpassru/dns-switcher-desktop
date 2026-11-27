import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

function detectTargetTriple() {
  if (process.env.TAURI_ENV_TARGET_TRIPLE) {
    return process.env.TAURI_ENV_TARGET_TRIPLE.trim();
  }
  const out = execFileSync("rustc", ["-vV"], { encoding: "utf8" });
  const match = out.match(/^host:\s*(.+)$/m);
  if (!match) {
    throw new Error("Could not determine rustc host target triple");
  }
  return match[1].trim();
}

const triple = detectTargetTriple();
const isRelease =
  process.argv.includes("--release") || process.env.NODE_ENV === "production";
const isWindows = triple.includes("windows");
const exeSuffix = isWindows ? ".exe" : "";

const cargoArgs = ["build", "--manifest-path", path.join(rootDir, "Cargo.toml"), "-p", "dns-bridge"];
if (isRelease) {
  cargoArgs.push("--release");
}
if (process.env.TAURI_ENV_TARGET_TRIPLE) {
  cargoArgs.push("--target", triple);
}

console.log(`[build-bridge] Building dns-bridge (${isRelease ? "release" : "debug"}) for ${triple}...`);
execFileSync("cargo", cargoArgs, { stdio: "inherit", cwd: rootDir });

const profileDir = isRelease ? "release" : "debug";
const srcBin = process.env.TAURI_ENV_TARGET_TRIPLE
  ? path.join(rootDir, "target", triple, profileDir, `dns-switcher-bridge${exeSuffix}`)
  : path.join(rootDir, "target", profileDir, `dns-switcher-bridge${exeSuffix}`);

if (!fs.existsSync(srcBin)) {
  throw new Error(`Expected built bridge binary at ${srcBin}`);
}

const binariesDir = path.join(rootDir, "src-tauri", "binaries");
fs.mkdirSync(binariesDir, { recursive: true });
const destBin = path.join(binariesDir, `dns-switcher-bridge-${triple}${exeSuffix}`);
fs.copyFileSync(srcBin, destBin);

if (!isWindows) {
  fs.chmodSync(destBin, 0o755);
}

console.log(`[build-bridge] Copied sidecar binary to ${destBin}`);
