// Test-owned transport fault injection; authentication remains owned by the real Gateway.
import { randomBytes } from "node:crypto";
import http from "node:http";
import https from "node:https";
import type { Socket } from "node:net";
import type { TlsOptions } from "node:tls";
import { WebSocket, WebSocketServer, type RawData } from "ws";

type Setup = {
  url: string;
  tlsFingerprint: string;
  bootstrapToken: string;
  expiresAtMs: number;
};
type Certificate = { options: TlsOptions; fingerprint: string };
type Mode = "normal" | "redirect" | "challenge" | "cookie" | "wrongCertificate" | "barrier";
type Endpoint = "primary" | "alternate" | "plaintext";
type Command = {
  command: "mode" | "snapshot" | "rotate" | "release" | "setup";
  mode?: Mode;
  target?: "host" | "port" | "path" | "plaintext";
  status?: 302 | 307;
  afterUpgrades?: number;
  cookieName?: string;
};

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function parseCommand(body: string): Command {
  const value = object(JSON.parse(body));
  if (!value || !["mode", "snapshot", "rotate", "release", "setup"].includes(String(value.command))) {
    throw new Error("unknown fixture command");
  }
  if (value.command === "mode") {
    if (
      !["normal", "redirect", "challenge", "cookie", "wrongCertificate", "barrier"].includes(
        String(value.mode),
      )
    ) {
      throw new Error("unknown transport mode");
    }
    if (
      value.target !== undefined &&
      !["host", "port", "path", "plaintext"].includes(String(value.target))
    ) {
      throw new Error("unknown redirect target");
    }
    if (value.status !== undefined && value.status !== 302 && value.status !== 307) {
      throw new Error("redirect status must be 302 or 307");
    }
    if (
      value.afterUpgrades !== undefined &&
      (typeof value.afterUpgrades !== "number" ||
        !Number.isSafeInteger(value.afterUpgrades) ||
        value.afterUpgrades < 0)
    ) {
      throw new Error("afterUpgrades must be a nonnegative integer");
    }
    if (
      value.cookieName !== undefined &&
      (typeof value.cookieName !== "string" || !/^[A-Za-z0-9_-]{1,100}$/.test(value.cookieName))
    ) {
      throw new Error("invalid synthetic cookie name");
    }
  }
  return value as Command;
}

async function listen(server: http.Server | https.Server, port = 0, host = "127.0.0.1"): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("fixture listener has no port");
  }
  return address.port;
}

export async function startPairingTransportFixture(params: {
  certificates: [Certificate, Certificate];
  backendURL: string;
  issueSetup: (url: string, fingerprint: string) => Promise<Setup>;
  rotateGateway: () => Promise<void>;
}) {
  let activeCertificate = 0;
  let configuration: Command = { command: "mode", mode: "normal" };
  let upgrades = 0;
  let barrierReached = false;
  const requests: Array<{
    endpoint: Endpoint | "redirected";
    method: string;
    path: string;
    headers: Record<string, string>;
  }> = [];
  const connects: Array<{
    endpoint: Endpoint | "redirected";
    role: string | null;
    auth: Record<string, unknown>;
    id: string | null;
  }> = [];
  const errors: string[] = [];
  // Count accepted TCP connections to TLS listeners, including trust failures
  // that abort before Node's secureConnection event can fire.
  const tlsConnections = { primary: 0, alternate: 0 };
  const sockets = new Set<Socket>();
  const connections = new Set<() => void>();
  const releases = new Set<() => void>();
  const responseCookies = new WeakMap<http.IncomingMessage, string>();
  const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 * 1024 });
  const primary = https.createServer(params.certificates[0].options);
  const primaryIPv6 = https.createServer(params.certificates[0].options);
  const alternate = https.createServer(params.certificates[0].options);
  const plaintext = http.createServer();
  const control = http.createServer();
  let primaryPort = 0;
  let alternatePort = 0;
  let plaintextPort = 0;
  let controlURL = "";
  let setup: Setup;

  function recordRequest(request: http.IncomingMessage, endpoint: Endpoint) {
    const redirected =
      endpoint === "primary" &&
      configuration.mode === "redirect" &&
      ((configuration.target === "host" && request.headers.host?.startsWith("localhost:")) ||
        (configuration.target === "path" && request.url?.startsWith("/redirected")));
    const label = redirected ? "redirected" : endpoint;
    const headers = Object.fromEntries(
      Object.entries(request.headers).map(([key, value]) => [
        key,
        Array.isArray(value) ? value.join(", ") : (value ?? ""),
      ]),
    );
    requests.push({ endpoint: label, method: request.method ?? "", path: request.url ?? "", headers });
    return label;
  }

  function terminatePeers() {
    for (const close of connections) {
      close();
    }
    for (const socket of sockets) {
      socket.destroy();
    }
    releases.clear();
  }

  function resetRecords() {
    requests.length = 0;
    connects.length = 0;
    errors.length = 0;
    upgrades = 0;
    barrierReached = false;
    tlsConnections.primary = 0;
    tlsConnections.alternate = 0;
  }

  function installCertificate(index: number) {
    for (const server of [primary, primaryIPv6, alternate]) {
      server.setSecureContext(params.certificates[index].options);
      // Existing sessions must not resume across a certificate change.
      server.setTicketKeys(randomBytes(48));
    }
  }

  function proxy(client: WebSocket, endpoint: Endpoint | "redirected", barrier: boolean) {
    const upstream = new WebSocket(params.backendURL, {
      ca: params.certificates[activeCertificate].options.cert,
      // Synthetic self-signed Gateway certificates have a fixture CN, not an IP SAN.
      // The explicit CA still verifies the actual backend certificate.
      checkServerIdentity: () => undefined,
      rejectUnauthorized: true,
      handshakeTimeout: 10_000,
    });
    const pending: Array<{ data: RawData; binary: boolean }> = [];
    const held: Array<{ data: RawData; binary: boolean }> = [];
    const bootstrapRequests = new Set<string>();
    let holding = false;
    let released = false;
    let closed = false;
    let barrierTimeout: ReturnType<typeof setTimeout> | undefined;
    const release = () => {
      released = true;
      holding = false;
      clearTimeout(barrierTimeout);
      releases.delete(release);
      for (const frame of held.splice(0)) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(frame.data, { binary: frame.binary });
        }
      }
    };
    const close = () => {
      if (closed) {
        return;
      }
      closed = true;
      clearTimeout(barrierTimeout);
      releases.delete(release);
      connections.delete(close);
      client.terminate();
      upstream.terminate();
    };
    connections.add(close);
    client.once("close", close);
    upstream.once("close", close);
    for (const peer of [client, upstream]) {
      peer.once("error", (error) => {
        if (!closed) {
          errors.push(error.message);
        }
        close();
      });
    }
    client.on("message", (data, binary) => {
      // URLSession sends JSON in binary WebSocket frames. Observe both opcodes,
      // but forward the original bytes and opcode without protocol translation.
      try {
        const frame = object(JSON.parse(data.toString()));
        const connect = object(frame?.params);
        if (frame?.type === "req" && frame.method === "connect" && connect) {
          const auth = object(connect.auth) ?? {};
          const id = typeof frame.id === "string" ? frame.id : null;
          connects.push({
            endpoint,
            role: typeof connect.role === "string" ? connect.role : null,
            auth,
            id,
          });
          if (id && typeof auth.bootstrapToken === "string" && auth.bootstrapToken.length > 0) {
            bootstrapRequests.add(id);
          }
        }
      } catch {
        // Malformed frames still go to the Gateway's actual protocol validator.
      }
      if (upstream.readyState === WebSocket.OPEN) {
        upstream.send(data, { binary });
      } else if (upstream.readyState === WebSocket.CONNECTING) {
        pending.push({ data, binary });
      }
    });
    upstream.once("open", () => {
      for (const frame of pending.splice(0)) {
        upstream.send(frame.data, { binary: frame.binary });
      }
    });
    upstream.on("message", (data, binary) => {
      if (barrier && !released && !holding) {
        try {
          const frame = object(JSON.parse(data.toString()));
          if (
            frame?.type === "res" &&
            frame.ok === true &&
            typeof frame.id === "string" &&
            bootstrapRequests.has(frame.id) &&
            object(frame.payload)?.type === "hello-ok"
          ) {
            holding = true;
            barrierReached = true;
            releases.add(release);
            barrierTimeout = setTimeout(() => {
              errors.push("bootstrap hello barrier was not released within 20 seconds");
              close();
            }, 20_000);
          }
        } catch {
          // Preserve the real Gateway response bytes.
        }
      }
      if (holding) {
        held.push({ data, binary });
      } else if (client.readyState === WebSocket.OPEN) {
        client.send(data, { binary });
      }
    });
  }

  wss.on("headers", (headers, request) => {
    const cookieName = responseCookies.get(request);
    if (cookieName) {
      headers.push(`Set-Cookie: ${cookieName}=sentinel; Path=/; Secure; HttpOnly`);
    }
  });

  for (const [server, endpoint] of [
    [primary, "primary"],
    [primaryIPv6, "primary"],
    [alternate, "alternate"],
    [plaintext, "plaintext"],
  ] as const) {
    server.on("connection", (socket) => {
      sockets.add(socket);
      if (endpoint !== "plaintext") {
        tlsConnections[endpoint] += 1;
      }
      socket.once("close", () => sockets.delete(socket));
    });
    server.on("request", (request, response) => {
      recordRequest(request, endpoint);
      response.writeHead(426).end();
    });
    server.on("upgrade", (request, socket, head) => {
      const label = recordRequest(request, endpoint);
      const eligible = label === "primary" && upgrades++ >= (configuration.afterUpgrades ?? 0);
      const mode = eligible ? configuration.mode : "normal";
      if (mode === "redirect") {
        const target = configuration.target ?? "port";
        const location =
          target === "host"
            ? `wss://localhost:${primaryPort}`
            : target === "path"
              ? `wss://127.0.0.1:${primaryPort}/redirected`
              : target === "plaintext"
                ? `ws://127.0.0.1:${plaintextPort}/redirected`
                : `wss://127.0.0.1:${alternatePort}/redirected`;
        socket.end(
          `HTTP/1.1 ${configuration.status ?? 302} Redirect\r\nLocation: ${location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
        );
        return;
      }
      if (mode === "challenge") {
        socket.end(
          `HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="native-proof"\r\nSet-Cookie: ${configuration.cookieName ?? "native-proof-response"}=sentinel; Path=/; Secure; HttpOnly\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
        );
        return;
      }
      if (mode === "cookie") {
        responseCookies.set(request, configuration.cookieName ?? "native-proof-response");
      }
      wss.handleUpgrade(request, socket, head, (client) => proxy(client, label, mode === "barrier"));
    });
  }

  const snapshot = () => ({
    setup: { ...setup, controlURL },
    requests,
    connects,
    tlsConnections,
    barrierReached,
    errors,
  });
  let commands = Promise.resolve();
  control.requestTimeout = 10_000;
  control.headersTimeout = 10_000;
  control.on("request", (request, response) => {
    if (request.method !== "POST" || request.url !== "/control") {
      response.writeHead(404).end();
      return;
    }
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
      if (body.length > 8192) {
        request.destroy();
      }
    });
    request.on("error", () => response.destroy());
    request.on("end", () => {
      commands = commands.then(async () => {
        try {
          const command = parseCommand(body);
          if (command.command === "mode") {
            terminatePeers();
            configuration = command;
            installCertificate(
              command.mode === "wrongCertificate" ? 1 - activeCertificate : activeCertificate,
            );
            resetRecords();
          } else if (command.command === "rotate") {
            terminatePeers();
            await params.rotateGateway();
            activeCertificate = 1;
            configuration = { command: "mode", mode: "normal" };
            installCertificate(activeCertificate);
            resetRecords();
            setup = await params.issueSetup(
              `wss://127.0.0.1:${primaryPort}`,
              params.certificates[activeCertificate].fingerprint,
            );
          } else if (command.command === "setup") {
            setup = await params.issueSetup(
              `wss://127.0.0.1:${primaryPort}`,
              params.certificates[activeCertificate].fingerprint,
            );
          } else if (command.command === "release") {
            for (const release of releases) {
              release();
            }
          }
          response
            .writeHead(200, { "Content-Type": "application/json" })
            .end(JSON.stringify(snapshot()));
        } catch (error) {
          response
            .writeHead(500, { "Content-Type": "application/json" })
            .end(JSON.stringify({ error: String(error) }));
        }
      });
    });
  });

  async function close() {
    terminatePeers();
    wss.close();
    await Promise.all(
      [primary, primaryIPv6, alternate, plaintext, control].map(
        (server) =>
          new Promise<void>((resolve) => {
            server.closeAllConnections();
            server.close(() => resolve());
          }),
      ),
    );
  }
  try {
    primaryPort = await listen(primary);
    // localhost may resolve to ::1 first on macOS. Both addresses must reach
    // the same recording target so a followed redirect cannot escape detection.
    await listen(primaryIPv6, primaryPort, "::1");
    alternatePort = await listen(alternate);
    plaintextPort = await listen(plaintext);
    controlURL = `http://127.0.0.1:${await listen(control)}/control`;
    setup = await params.issueSetup(
      `wss://127.0.0.1:${primaryPort}`,
      params.certificates[0].fingerprint,
    );
    return { setup: { ...setup, controlURL }, close };
  } catch (error) {
    await close();
    throw error;
  }
}
