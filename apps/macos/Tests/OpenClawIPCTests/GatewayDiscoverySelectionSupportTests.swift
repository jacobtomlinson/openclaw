import Foundation
import OpenClawDiscovery
import Testing
@testable import OpenClaw

@Suite(.serialized)
@MainActor
struct GatewayDiscoverySelectionSupportTests {
    private static let preferenceDefaults: [String: Any?] = [
        "gateway.preferredStableID": nil,
        "bridge.preferredStableID": nil,
        "gateway.preferredStableIDRouteBinding.v1": nil,
        "gateway.preferredTLSFingerprint.v1": nil,
    ]

    @Test func `secure setup requires TLS pin and bootstrap credential`() throws {
        let fingerprint = String(repeating: "ab", count: 32)
        let valid = """
        {"url":"wss://gateway.local:18789","tlsFingerprint":"\(fingerprint)","bootstrapToken":"one-time"}
        """
        let link = try GatewayDiscoveryPairing.parseSetup(valid)
        #expect(link.websocketURL?.absoluteString == "wss://gateway.local:18789")
        #expect(link.tlsFingerprintSha256 == fingerprint)

        let missingPin = #"{"url":"wss://gateway.local:18789","bootstrapToken":"one-time"}"#
        #expect(throws: GatewayDiscoveryPairingError.secureSetupRequired) {
            try GatewayDiscoveryPairing.parseSetup(missingPin)
        }

        let plaintext = """
        {"url":"ws://gateway.local:18789","tlsFingerprint":"\(fingerprint)","bootstrapToken":"one-time"}
        """
        #expect(throws: GatewayDiscoveryPairingError.invalidSetupCode) {
            try GatewayDiscoveryPairing.parseSetup(plaintext)
        }
    }

    @Test func `server rejections classify as actionable pairing errors`() {
        let rejectedCode = "unauthorized: setup code invalid, expired, revoked, or already used " +
            "(create a new code; review `openclaw devices list`)"
        #expect(GatewayDiscoveryPairing.classifyServerRejection(rejectedCode) == .invalidSetupCode)
        #expect(GatewayDiscoveryPairing.classifyServerRejection(
            "unauthorized: gateway token missing (provide gateway auth token)") == .gatewayTooOld)
        #expect(GatewayDiscoveryPairing.classifyServerRejection(
            "unauthorized: too many failed authentication attempts (retry later)") == nil)
        #expect(GatewayDiscoveryPairing.classifyServerRejection("connect failed (missing payload)") == nil)

        let tooOld = GatewayDiscoveryPairingError.gatewayTooOld.errorDescription
        #expect(tooOld?.contains("v2026.9.3") == true)
        #expect(tooOld?.contains("SSH tunnel") == true)
        #expect(tooOld?.contains("do not need to match") == true)
    }

    @Test func `authenticated route suppresses shared auth and owns its device token`() async throws {
        let configPath = TestIsolation.tempConfigPath()
        let fingerprint = String(repeating: "cd", count: 32)
        let url = "wss://gateway.local:18789"
        try Data("""
        {"gateway":{"mode":"remote","remote":{"transport":"direct","url":"\(url)","token":"config-token","password":"config-password","tlsFingerprint":"\(fingerprint)"}}}
        """.utf8).write(to: URL(fileURLWithPath: configPath))
        defer { try? FileManager.default.removeItem(atPath: configPath) }

        try await TestIsolation.withIsolatedState(
            env: [
                "OPENCLAW_CONFIG_PATH": configPath,
                "OPENCLAW_GATEWAY_TOKEN": "ambient-token",
                "OPENCLAW_GATEWAY_PASSWORD": "ambient-password",
            ],
            defaults: Self.preferenceDefaults)
        {
            let state = AppState(preview: true)
            state.connectionMode = .remote
            state.remoteTransport = .direct
            state.remoteUrl = url
            GatewayDiscoveryPreferences.setAuthenticatedPreferredGateway(
                stableID: "bonjour|gateway",
                tlsFingerprint: fingerprint)

            let source = try await GatewayEndpointStore._testLiveSourceSnapshot(
                state: state,
                profile: AppProfile(environment: [:]),
                beforeConfigRead: {})

            #expect(source.token == nil)
            #expect(source.password == nil)
            #expect(source.deviceAuthGatewayID == "tls-sha256:\(fingerprint)")
            #expect(source.remoteTLSFingerprint == fingerprint)
        }
    }

    @Test func `plaintext downgrade retires certificate credential ownership`() async throws {
        let configPath = TestIsolation.tempConfigPath()
        let fingerprint = String(repeating: "de", count: 32)
        let url = "ws://gateway.local:18789"
        try Data("""
        {"gateway":{"mode":"remote","remote":{"transport":"direct","url":"\(url)","token":"config-token","password":"config-password","tlsFingerprint":"\(fingerprint)"}}}
        """.utf8).write(to: URL(fileURLWithPath: configPath))
        defer { try? FileManager.default.removeItem(atPath: configPath) }

        try await TestIsolation.withIsolatedState(
            env: [
                "OPENCLAW_CONFIG_PATH": configPath,
                "OPENCLAW_GATEWAY_TOKEN": "ambient-token",
                "OPENCLAW_GATEWAY_PASSWORD": "ambient-password",
            ],
            defaults: Self.preferenceDefaults)
        {
            let state = AppState(preview: true)
            state.connectionMode = .remote
            state.remoteTransport = .direct
            state.remoteUrl = url
            GatewayDiscoveryPreferences.setAuthenticatedPreferredGateway(
                stableID: "bonjour|gateway",
                tlsFingerprint: fingerprint)

            let source = try await GatewayEndpointStore._testLiveSourceSnapshot(
                state: state,
                profile: AppProfile(environment: [:]),
                beforeConfigRead: {})

            #expect(source.token == nil)
            #expect(source.password == nil)
            let routeOwner = try #require(GatewayDiscoveryPreferences.routeBinding(
                connectionMode: .remote,
                remoteTransport: .direct,
                remoteURL: url,
                remoteTarget: ""))
            #expect(source.deviceAuthGatewayID == routeOwner)
            #expect(!routeOwner.hasPrefix("tls-sha256:"))
            #expect(source.remoteTLSFingerprint == fingerprint)
        }
    }

    @Test func `selection fence reports only the pairing it retires`() {
        let fence = GatewayDiscoverySelectionFence()
        _ = fence.begin()

        #expect(fence.invalidate())
        #expect(!fence.invalidate())
    }

    @Test func `authenticated selection replaces shared auth with pinned device identity`() async throws {
        let configPath = TestIsolation.tempConfigPath()
        let fingerprint = String(repeating: "56", count: 32)
        try await TestIsolation.withIsolatedState(
            env: ["OPENCLAW_CONFIG_PATH": configPath],
            defaults: Self.preferenceDefaults)
        {
            let state = AppState(preview: true)
            state.connectionMode = .remote
            state.remoteTransport = .direct
            state.remoteUrl = "wss://old-gateway.local:18789"
            state.remoteToken = "old-shared-token"
            state._testEnableGatewayConfigSync()
            let fence = GatewayDiscoverySelectionFence()
            let lease = fence.begin()

            let applied = GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
                stableID: "bonjour|new-gateway",
                route: AuthenticatedGatewayRoute(
                    url: try #require(URL(string: "wss://new-gateway.local:18789")),
                    tlsFingerprint: fingerprint),
                state: state,
                lease: lease,
                fence: fence)

            #expect(applied == .applied)
            #expect(state.remoteUrl == "wss://new-gateway.local:18789")
            #expect(state.remoteToken.isEmpty)
            #expect(GatewayDiscoveryPreferences.preferredStableID() == "bonjour|new-gateway")
            #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == fingerprint)
            let remote = (OpenClawConfigFile.loadDict()["gateway"] as? [String: Any])?["remote"]
                as? [String: Any]
            #expect(remote?["token"] == nil)
            #expect(remote?["password"] == nil)
            #expect(remote?["tlsFingerprint"] as? String == fingerprint)
        }
    }

    @Test func `authenticated selection failure preserves prior route and trust`() async throws {
        let configPath = TestIsolation.tempConfigPath()
        let previousFingerprint = String(repeating: "45", count: 32)
        let replacementFingerprint = String(repeating: "67", count: 32)
        defer { try? FileManager.default.removeItem(atPath: configPath) }

        try await TestIsolation.withIsolatedState(
            env: ["OPENCLAW_CONFIG_PATH": configPath],
            defaults: Self.preferenceDefaults)
        {
            #expect(OpenClawConfigFile.saveDict([
                "gateway": [
                    "mode": "remote",
                    "remote": [
                        "transport": "direct",
                        "url": "wss://old-gateway.local:18789",
                        "token": "old-shared-token",
                        "tlsFingerprint": previousFingerprint,
                    ],
                ],
            ]))
            let state = AppState(
                preview: true,
                gatewayConfigSaver: { _, _ in false })
            state.connectionMode = .remote
            state.remoteTransport = .direct
            state.remoteUrl = "wss://old-gateway.local:18789"
            state.remoteToken = "old-shared-token"
            state._testEnableGatewayConfigSync()
            GatewayDiscoveryPreferences.setAuthenticatedPreferredGateway(
                stableID: "bonjour|old-gateway",
                tlsFingerprint: previousFingerprint)
            let fence = GatewayDiscoverySelectionFence()
            let lease = fence.begin()

            let applied = GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
                stableID: "bonjour|new-gateway",
                route: AuthenticatedGatewayRoute(
                    url: try #require(URL(string: "wss://new-gateway.local:18789")),
                    tlsFingerprint: replacementFingerprint),
                state: state,
                lease: lease,
                fence: fence)

            #expect(applied == .saveFailed)
            #expect(state.remoteUrl == "wss://old-gateway.local:18789")
            #expect(state.remoteToken == "old-shared-token")
            #expect(GatewayDiscoveryPreferences.preferredStableID() == "bonjour|old-gateway")
            #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == previousFingerprint)
            let remote = (OpenClawConfigFile.loadDict()["gateway"] as? [String: Any])?["remote"]
                as? [String: Any]
            #expect(remote?["url"] as? String == "wss://old-gateway.local:18789")
            #expect(remote?["token"] as? String == "old-shared-token")
            #expect(remote?["tlsFingerprint"] as? String == previousFingerprint)
        }
    }

    @Test func `superseded pairing cannot publish its authenticated route`() async throws {
        let configPath = TestIsolation.tempConfigPath()
        let fingerprint = String(repeating: "78", count: 32)
        try await TestIsolation.withIsolatedState(
            env: ["OPENCLAW_CONFIG_PATH": configPath],
            defaults: Self.preferenceDefaults)
        {
            let state = AppState(preview: true)
            state.connectionMode = .remote
            state.remoteTransport = .direct
            state.remoteUrl = "wss://current-gateway.local:18789"
            state._testEnableGatewayConfigSync()
            let fence = GatewayDiscoverySelectionFence()
            let staleLease = fence.begin()
            _ = fence.begin()

            let result = GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
                stableID: "bonjour|obsolete-gateway",
                route: AuthenticatedGatewayRoute(
                    url: try #require(URL(string: "wss://obsolete-gateway.local:18789")),
                    tlsFingerprint: fingerprint),
                state: state,
                lease: staleLease,
                fence: fence)

            #expect(result == .superseded)
            #expect(state.remoteUrl == "wss://current-gateway.local:18789")
            #expect(GatewayDiscoveryPreferences.preferredStableID() == nil)
            #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == nil)
        }
    }

    @Test func `legacy discovery preference cannot claim an authenticated route`() async throws {
        let configPath = TestIsolation.tempConfigPath()
        let fingerprint = String(repeating: "ef", count: 32)
        let url = "wss://gateway.local:18789"
        try Data("""
        {"gateway":{"mode":"remote","remote":{"transport":"direct","url":"\(url)","token":"config-token","tlsFingerprint":"\(fingerprint)"}}}
        """.utf8).write(to: URL(fileURLWithPath: configPath))
        defer { try? FileManager.default.removeItem(atPath: configPath) }

        try await TestIsolation.withIsolatedState(
            env: [
                "OPENCLAW_CONFIG_PATH": configPath,
                "OPENCLAW_GATEWAY_TOKEN": nil,
            ],
            defaults: Self.preferenceDefaults)
        {
            let state = AppState(preview: true)
            state.connectionMode = .remote
            state.remoteTransport = .direct
            state.remoteUrl = url
            let binding = try #require(GatewayDiscoveryPreferences.routeBinding(
                connectionMode: .remote,
                remoteTransport: .direct,
                remoteURL: url,
                remoteTarget: ""))
            GatewayDiscoveryPreferences.setPreferredStableID(
                "bonjour|gateway",
                routeBinding: binding)

            let source = try await GatewayEndpointStore._testLiveSourceSnapshot(
                state: state,
                profile: AppProfile(environment: [:]),
                beforeConfigRead: {})

            #expect(source.token == "config-token")
            #expect(source.deviceAuthGatewayID == binding)
        }
    }

    @Test func `certificate change retires authenticated credential ownership`() async throws {
        let trusted = String(repeating: "12", count: 32)
        let replacement = String(repeating: "34", count: 32)
        await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            GatewayDiscoveryPreferences.setAuthenticatedPreferredGateway(
                stableID: "bonjour|gateway",
                tlsFingerprint: trusted)

            #expect(GatewayDiscoveryPreferences.hasAuthenticatedTLSIdentity(
                configuredFingerprint: "SHA256:\(trusted.uppercased())"))
            #expect(!GatewayDiscoveryPreferences.hasAuthenticatedTLSIdentity(
                configuredFingerprint: replacement))
            #expect(GatewayDiscoveryPreferences.deviceAuthGatewayID(
                connectionMode: .remote,
                remoteTransport: .direct,
                remoteURL: "wss://gateway.local:18789",
                remoteTarget: "",
                tlsFingerprint: replacement) != "tls-sha256:\(trusted)")
            #expect(GatewayDiscoveryPreferences.deviceAuthGatewayID(
                connectionMode: .remote,
                remoteTransport: .direct,
                remoteURL: "ws://gateway.local:18789",
                remoteTarget: "",
                tlsFingerprint: trusted) != "tls-sha256:\(trusted)")
        }
    }
}
