import Darwin
import Foundation
import OpenClawKit
import Testing
@testable import OpenClaw

/// Control traffic and synthetic credentials exist only inside the opt-in disposable native proof.
@MainActor
final class GatewayPairingNativeProofFixture {
    struct Setup: Codable, Sendable {
        var url: URL
        let tlsFingerprint: String
        var bootstrapToken: String
        let expiresAtMs: Double
        let controlURL: URL

        var input: String {
            get throws {
                try #require(String(data: JSONEncoder().encode(self), encoding: .utf8))
            }
        }
    }

    struct Observation: Decodable, Sendable {
        struct Request: Decodable, Sendable {
            let endpoint: String
            let method: String
            let path: String
            let headers: [String: String]
        }

        struct Connect: Decodable, Sendable {
            let endpoint: String
            let role: String?
            let auth: [String: String]
            let id: String?
        }

        let setup: Setup
        let requests: [Request]
        let connects: [Connect]
        let tlsConnections: [String: Int]
        let barrierReached: Bool
        let errors: [String]
    }

    private let child: Process
    private let output: FileHandle
    private let controlSession: URLSession
    let setup: Setup

    private init(child: Process, output: FileHandle, setup: Setup) {
        self.child = child
        self.output = output
        self.setup = setup
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 45
        self.controlSession = URLSession(configuration: configuration)
    }

    static func start() async throws -> GatewayPairingNativeProofFixture {
        let environment = ProcessInfo.processInfo.environment
        let statePath = try #require(environment["OPENCLAW_STATE_DIR"])
        let root = URL(fileURLWithPath: statePath).resolvingSymlinksInPath()
            .deletingLastPathComponent().appendingPathComponent("pairing-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let setupURL = root.appendingPathComponent("gateway-setup.json")
        let readyURL = root.appendingPathComponent("gateway-ready")
        let logURL = root.appendingPathComponent("gateway.log")
        var repo = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { repo.deleteLastPathComponent() }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        child.arguments = [
            "node", "--import", "tsx",
            repo.appendingPathComponent(
                "test/e2e/qa-lab/runtime/macos-gateway-discovery-pairing.native.test-support.ts").path,
            setupURL.path, readyURL.path, root.appendingPathComponent("gateway-state").path,
        ]
        child.currentDirectoryURL = repo
        child.environment = environment
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
        let output = try FileHandle(forWritingTo: logURL)
        child.standardOutput = output
        child.standardError = output
        do {
            try child.run()
            let deadline = ContinuousClock.now + .seconds(120)
            while !FileManager.default.fileExists(atPath: readyURL.path) {
                guard child.isRunning else {
                    throw NSError(domain: "GatewayPairingProof", code: Int(child.terminationStatus), userInfo: [
                        NSLocalizedDescriptionKey: "The real Gateway exited before readiness; see \(logURL.path)",
                    ])
                }
                guard ContinuousClock.now < deadline else { throw URLError(.timedOut) }
                try await Task.sleep(for: .milliseconds(25))
            }
            let setup = try JSONDecoder().decode(Setup.self, from: Data(contentsOf: setupURL))
            return GatewayPairingNativeProofFixture(child: child, output: output, setup: setup)
        } catch {
            await self.stopChild(child)
            try? output.close()
            throw error
        }
    }

    func stop() async {
        self.controlSession.invalidateAndCancel()
        await Self.stopChild(self.child)
        try? self.output.close()
    }

    private static func stopChild(_ child: Process) async {
        // Cleanup must finish even when the test's waiting task was cancelled.
        await Task {
            if child.isRunning { child.terminate() }
            let deadline = ContinuousClock.now + .seconds(10)
            while child.isRunning, ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(25))
            }
            if child.isRunning {
                Issue.record("The owned Gateway fixture did not exit after SIGTERM")
                _ = Darwin.kill(child.processIdentifier, SIGKILL)
                let killDeadline = ContinuousClock.now + .seconds(2)
                while child.isRunning, ContinuousClock.now < killDeadline {
                    try? await Task.sleep(for: .milliseconds(25))
                }
            }
            #expect(!child.isRunning, "The native proof fixture must finish its owned child process")
        }.value
    }

    @discardableResult
    func command(_ command: String, fields: [String: Any] = [:]) async throws -> Observation {
        var body = fields
        body["command"] = command
        var request = URLRequest(url: self.setup.controlURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await self.controlSession.data(for: request)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        let observation = try JSONDecoder().decode(Observation.self, from: data)
        #expect(observation.errors.isEmpty)
        return observation
    }

    func waitForBarrier() async throws -> Observation {
        let deadline = ContinuousClock.now + .seconds(5)
        while ContinuousClock.now < deadline {
            let observation = try await self.command("snapshot")
            if observation.barrierReached { return observation }
            try await Task.sleep(for: .milliseconds(25))
        }
        throw URLError(.timedOut, userInfo: [NSLocalizedDescriptionKey: "Bootstrap response barrier was not reached"])
    }
}

/// Exercises the same TLS cache, option adapter, and node-session consumer as ordinary node mode.
@MainActor
final class GatewayPairingNativeProofNode {
    private var cache = MacNodeGatewayTLSSessionCache()
    let session = GatewayNodeSession()
    private(set) var admissions = 0
    private(set) var transportIdentity: ObjectIdentifier?

    func connect(_ endpoint: GatewayConnection.EndpointSnapshot) async throws {
        let options = MacNodeModeCoordinator.connectOptions(
            GatewayConnectOptions(
                role: "node", scopes: [], caps: [], commands: [], permissions: [:],
                clientId: "openclaw-macos", clientMode: "node",
                clientDisplayName: "macOS Gateway pairing proof", deviceIdentityProfile: .node),
            for: endpoint)
        #expect(options.deviceIdentityProfile == .primary)
        let tls = try #require(endpoint.tls)
        let box = self.cache.sessionBox(url: endpoint.config.url, params: tls.params)
        self.transportIdentity = ObjectIdentifier(box.session)
        try await self.session.connect(
            url: endpoint.config.url,
            token: endpoint.config.token,
            password: endpoint.config.password,
            connectOptions: options,
            sessionBox: box,
            onConnected: { [weak self] in await self?.didConnect() },
            onDisconnected: { _ in },
            onInvoke: { request in BridgeInvokeResponse(id: request.id, ok: false) })
        #expect(await self.session.currentRoute(ifGatewayID: endpoint.deviceAuthGatewayID) != nil)
    }

    func disconnect() async {
        await self.session.disconnect()
    }

    private func didConnect() {
        self.admissions += 1
    }
}
