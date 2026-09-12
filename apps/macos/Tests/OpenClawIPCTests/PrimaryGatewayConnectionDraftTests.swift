import Foundation
import OpenClawKit
import Testing
@testable import OpenClaw

@Suite(.serialized)
@MainActor
struct PrimaryGatewayConnectionDraftTests {
    private let savedURL = "wss://saved.example.test/"
    private let pin = String(repeating: "a", count: 64)

    private func withSavedConnection(
        remote: [String: Any]? = nil,
        localPort: Int? = nil,
        _ body: @MainActor (AppState, [String: Any]) async throws -> Void) async throws
    {
        let directory = try makeTempDirForTests()
        defer { try? FileManager.default.removeItem(at: directory) }
        try await TestIsolation.withEnvValues([
            "OPENCLAW_CONFIG_PATH": directory.appendingPathComponent("openclaw.json").path,
        ]) {
            var gateway: [String: Any] = [
                "mode": "remote",
                "remote": remote ?? [
                    "transport": "direct", "url": self.savedURL,
                    "token": "saved-test-token", "password": "saved-test-password",
                    "tlsFingerprint": self.pin,
                ],
            ]
            if let localPort { gateway["port"] = localPort }
            let root: [String: Any] = ["gateway": gateway]
            #expect(OpenClawConfigFile.saveDict(root))
            let state = AppState(preview: true)
            state._testEnableGatewayConfigSync()
            try await body(state, root)
            await state._testAwaitGatewayConfigSync()
        }
    }

    @Test(arguments: ["input", "transport", "ssh-target", "remote-port"])
    func `editing a destination clears the draft credentials without changing the saved connection`(
        field: String) async throws
    {
        try await self.withSavedConnection { state, root in
            let draft = PrimaryGatewayConnectionDraft(state: state)
            switch field {
            case "input": draft.input = "wss://new.example.test"
            case "transport": draft.transport = .ssh
            case "ssh-target": draft.sshTarget = "user@new.example.test:2222"
            default: draft.remotePort = "29876"
            }
            #expect(draft.token.isEmpty)
            #expect(draft.password.isEmpty)
            #expect(state.remoteUrl == self.savedURL)
            #expect(state.remoteToken == "saved-test-token")
            #expect(NSDictionary(dictionary: OpenClawConfigFile.loadDict()["gateway"] as? [String: Any] ?? [:])
                .isEqual(to: root["gateway"] as? [String: Any] ?? [:]))
        }
    }

    @Test(arguments: ["token", "password"], [false, true])
    func `trusted code import saves its endpoint and pin with ordinary authentication`(
        auth: String, encoded: Bool) async throws
    {
        try await self.withSavedConnection { state, _ in
            let draft = PrimaryGatewayConnectionDraft(state: state)
            let code = """
            {"url":"wss://new.example.test:19876/gateway","tlsFingerprint":"\(self.pin)",
             "bootstrapToken":"unused-bootstrap-test-token"}
            """
            draft.input = encoded ? Data(code.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "") : code
            if auth == "token" { draft.token = "new-test-token" }
            else { draft.password = "new-test-password" }

            try draft.save()

            let root = OpenClawConfigFile.loadDict()
            #expect(GatewayRemoteConfig.resolveUrlString(root: root) == "wss://new.example.test:19876/gateway")
            #expect(GatewayRemoteConfig.resolveTokenString(root: root) == (auth == "token" ? "new-test-token" : nil))
            #expect(GatewayRemoteConfig.resolvePasswordString(root: root) ==
                (auth == "password" ? "new-test-password" : nil))
            #expect(GatewayRemoteConfig.resolveTLSFingerprint(root: root) == self.pin)
        }
    }

    @Test func `saving an unchanged direct address retains its device-token route key`() async throws {
        try await self.withSavedConnection { state, root in
            let before = GatewayDiscoveryPreferences.deviceAuthGatewayID(root: root)
            let draft = PrimaryGatewayConnectionDraft(state: state)
            try draft.save()
            let after = OpenClawConfigFile.loadDict()
            #expect(GatewayRemoteConfig.resolveUrlString(root: after) == self.savedURL)
            #expect(GatewayDiscoveryPreferences.deviceAuthGatewayID(root: after) == before)
            #expect(GatewayRemoteConfig.resolveTokenString(root: after) == "saved-test-token")
            #expect(GatewayRemoteConfig.resolvePasswordString(root: after) == "saved-test-password")
            #expect(GatewayRemoteConfig.resolveTLSFingerprint(root: after) == self.pin)
        }
    }

    @Test func `legacy SSH port is preserved when editing only authentication`() async throws {
        try await self.withSavedConnection(remote: [
            "transport": "ssh", "sshTarget": "user@saved.example.test:2222",
            "url": "ws://127.0.0.1:29876", "token": "saved-test-token",
        ]) { state, root in
            let before = GatewayDiscoveryPreferences.deviceAuthGatewayID(root: root)
            let draft = PrimaryGatewayConnectionDraft(state: state)
            #expect(draft.remotePort == "29876")
            draft.token = "replacement-test-token"
            try draft.save()
            let after = OpenClawConfigFile.loadDict()
            #expect(GatewayRemoteConfig.resolveRemotePort(root: after) == 29876)
            #expect(GatewayDiscoveryPreferences.deviceAuthGatewayID(root: after) == before)
        }
    }

    @Test(arguments: ["token", "password"])
    func `another plaintext credential does not silently replace an untouched credential reference`(
        referenceField: String) async throws
    {
        var remote: [String: Any] = [
            "transport": "direct", "url": self.savedURL,
            "token": "saved-test-token", "password": "saved-test-password",
        ]
        remote[referenceField] = ["source": "env", "provider": "default", "id": "SYNTHETIC_GATEWAY_SECRET"]
        try await self.withSavedConnection(remote: remote) { state, root in
            let draft = PrimaryGatewayConnectionDraft(state: state)
            #expect(throws: Error.self) { try draft.save() }
            #expect(NSDictionary(dictionary: OpenClawConfigFile.loadDict()["gateway"] as? [String: Any] ?? [:])
                .isEqual(to: root["gateway"] as? [String: Any] ?? [:]))
        }
    }

    @Test func `SSH credential edits retain separate local and remote port settings`() async throws {
        try await self.withSavedConnection(remote: [
            "transport": "ssh", "sshTarget": "user@saved.example.test:2222",
            "url": "ws://127.0.0.1:29876", "remotePort": 18789, "token": "saved-test-token",
        ], localPort: 29876) { state, _ in
            let draft = PrimaryGatewayConnectionDraft(state: state)
            #expect(draft.remotePort == "18789")
            draft.token = "replacement-test-token"

            try draft.save()

            let root = OpenClawConfigFile.loadDict()
            #expect(OpenClawConfigFile.gatewayPort(root: root) == 29876)
            #expect(GatewayRemoteConfig.resolveUrlString(root: root) == "ws://127.0.0.1:29876")
            #expect(GatewayRemoteConfig.resolveRemotePort(root: root) == 18789)
            #expect(GatewayRemoteConfig.resolveTokenString(root: root) == "replacement-test-token")
        }
    }

    @Test(arguments: [false, true])
    func `SSH host-key policy changes only when its SSH target changes`(changesTarget: Bool) async throws {
        try await self.withSavedConnection(remote: [
            "transport": "ssh", "sshTarget": "user@saved.example.test:2222",
            "url": "ws://127.0.0.1:18789", "sshHostKeyPolicy": "openssh", "token": "saved-test-token",
        ]) { state, _ in
            let draft = PrimaryGatewayConnectionDraft(state: state)
            if changesTarget { draft.sshTarget = "user@new.example.test:2222" }
            else { draft.remotePort = "29876" }
            try draft.save()
            let root = OpenClawConfigFile.loadDict()
            #expect(CommandResolver.connectionSettings(configRoot: root).sshHostKeyPolicy ==
                (changesTarget ? .strict : .openssh))
            #expect(GatewayRemoteConfig.resolveTokenString(root: root) == nil)
        }
    }

    @Test func `opening after a file edit reads one complete canonical destination and auth bundle`() async throws {
        try await self.withSavedConnection { state, _ in
            var edited = OpenClawConfigFile.loadDict()
            edited["gateway"] = ["mode": "remote", "remote": [
                "transport": "direct", "url": "wss://other.example.test/",
                "token": "other-test-token", "password": "other-test-password",
                "tlsFingerprint": String(repeating: "b", count: 64),
            ]]
            try #require(OpenClawConfigFile.saveDict(edited))
            #expect(state.remoteUrl == self.savedURL)
            let draft = PrimaryGatewayConnectionDraft(state: state)
            #expect(draft.input == "wss://other.example.test/")
            #expect(draft.token == "other-test-token")
            #expect(draft.password == "other-test-password")
            try draft.save()
            #expect(state.remoteUrl == "wss://other.example.test/")
            #expect(GatewayRemoteConfig.resolveTLSFingerprint(root: OpenClawConfigFile.loadDict()) ==
                String(repeating: "b", count: 64))
        }
    }
}
