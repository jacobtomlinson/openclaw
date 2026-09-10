// Real Gateway process used by the disposable macOS native pairing proof.
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { startPairingTransportFixture } from "./macos-gateway-discovery-pairing.transport.test-support.js";

async function getFreePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("failed to allocate a loopback port");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return address.port;
}

const [setupPath, readyPath, gatewayStateDir] = process.argv.slice(2);
if (!setupPath || !readyPath || !gatewayStateDir) {
  throw new Error("expected setup path, ready path, and Gateway state directory");
}

process.env.OPENCLAW_STATE_DIR = gatewayStateDir;
process.env.OPENCLAW_CONFIG_PATH = path.join(gatewayStateDir, "openclaw.json");
process.env.OPENCLAW_DISABLE_BONJOUR = "1";
process.env.OPENCLAW_DISABLE_BUNDLED_PLUGINS = "1";
process.env.OPENCLAW_SKIP_BROWSER_CONTROL_SERVER = "1";
process.env.OPENCLAW_SKIP_CANVAS_HOST = "1";
process.env.OPENCLAW_SKIP_CHANNELS = "1";
process.env.OPENCLAW_SKIP_CRON = "1";
process.env.OPENCLAW_SKIP_GMAIL_WATCHER = "1";
process.env.OPENCLAW_SKIP_PROVIDERS = "1";
delete process.env.VITEST;

const [
  { clearConfigCache, clearRuntimeConfigSnapshot },
  { issueDevicePairSetupBootstrapToken },
  { startGatewayServer },
  { loadGatewayTlsServerRuntime },
  { FULL_ACCESS_PAIRING_SETUP_BOOTSTRAP_PROFILE },
] = await Promise.all([
  import("../../../../src/config/config.js"),
  import("../../../../src/infra/device-bootstrap.js"),
  import("../../../../src/gateway/server.js"),
  import("../../../../src/infra/tls/gateway.js"),
  import("../../../../src/shared/device-bootstrap-profile.js"),
]);

await fs.mkdir(gatewayStateDir, { recursive: true, mode: 0o700 });
const certPath = path.join(gatewayStateDir, "gateway-cert.pem");
const keyPath = path.join(gatewayStateDir, "gateway-key.pem");
const rotatedCertPath = path.join(gatewayStateDir, "gateway-cert-b.pem");
const rotatedKeyPath = path.join(gatewayStateDir, "gateway-key-b.pem");
const tls = await loadGatewayTlsServerRuntime({
  enabled: true,
  autoGenerate: true,
  certPath,
  keyPath,
});
if (!tls.enabled || !tls.fingerprintSha256 || !tls.tlsOptions) {
  throw new Error(tls.error ?? "Gateway TLS runtime did not expose a fingerprint");
}
const rotatedTls = await loadGatewayTlsServerRuntime({
  enabled: true,
  autoGenerate: true,
  certPath: rotatedCertPath,
  keyPath: rotatedKeyPath,
});
if (!rotatedTls.enabled || !rotatedTls.fingerprintSha256 || !rotatedTls.tlsOptions) {
  throw new Error(rotatedTls.error ?? "Rotated Gateway TLS runtime did not expose a fingerprint");
}

async function writeConfig(certificatePath: string, privateKeyPath: string) {
  await fs.writeFile(
    path.join(gatewayStateDir, "openclaw.json"),
    `${JSON.stringify({
      gateway: {
        auth: { mode: "token", token: "native-proof-shared-token" },
        bind: "loopback",
        controlUi: { enabled: false },
        tls: { enabled: true, autoGenerate: false, certPath: certificatePath, keyPath: privateKeyPath },
      },
    })}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  clearConfigCache();
  clearRuntimeConfigSnapshot();
}

await writeConfig(certPath, keyPath);
const port = await getFreePort();
const serverOptions = {
  auth: { mode: "token", token: "native-proof-shared-token" },
  bind: "loopback",
  controlUiEnabled: false,
  sidecarStartup: "defer",
} as const;
let server = await startGatewayServer(port, serverOptions);
let transport: Awaited<ReturnType<typeof startPairingTransportFixture>> | undefined;

try {
  transport = await startPairingTransportFixture({
    certificates: [
      { options: tls.tlsOptions, fingerprint: tls.fingerprintSha256 },
      { options: rotatedTls.tlsOptions, fingerprint: rotatedTls.fingerprintSha256 },
    ],
    backendURL: `wss://127.0.0.1:${port}`,
    issueSetup: async (url, tlsFingerprint) => {
      const issued = await issueDevicePairSetupBootstrapToken({
        profile: FULL_ACCESS_PAIRING_SETUP_BOOTSTRAP_PROFILE,
      });
      return { url, tlsFingerprint, bootstrapToken: issued.token, expiresAtMs: issued.expiresAtMs };
    },
    rotateGateway: async () => {
      // Restart only this disposable Gateway. Device identity and both role
      // credentials stay in the same fixture-owned state directory.
      await server.close({ reason: "native pairing proof certificate rotation" });
      await writeConfig(rotatedCertPath, rotatedKeyPath);
      server = await startGatewayServer(port, serverOptions);
    },
  });
  await fs.writeFile(
    setupPath,
    `${JSON.stringify(transport.setup)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  await fs.writeFile(readyPath, "ready\n", { encoding: "utf8", mode: 0o600 });
  await new Promise<void>((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
} finally {
  await transport?.close();
  await server.close({ reason: "macOS discovery pairing proof complete" });
}
