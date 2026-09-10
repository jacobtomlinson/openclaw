import Foundation
import OpenClawDiscovery
import Testing
@testable import OpenClaw

@Suite(.serialized)
@MainActor
struct GatewayDiscoveryReconnectTests {
    private static let fingerprint = String(repeating: "ab", count: 32)
    private static let preferenceDefaults: [String: Any?] = [
        "gateway.preferredStableID": "bonjour|remembered",
        "bridge.preferredStableID": nil,
        "gateway.preferredStableIDRouteBinding.v1": nil,
        "gateway.preferredTLSFingerprint.v1": fingerprint,
    ]

    private static func gateway(
        stableID: String = "bonjour|remembered",
        serviceHost: String? = "moved-gateway.local") -> GatewayDiscoveryModel.DiscoveredGateway
    {
        GatewayDiscoveryModel.DiscoveredGateway(
            displayName: "Remembered Gateway",
            serviceHost: serviceHost,
            servicePort: 18790,
            lanHost: "untrusted-txt.local",
            tailnetDns: "untrusted-txt.example.ts.net",
            sshPort: 22,
            gatewayPort: 443,
            gatewayTls: false,
            stableID: stableID,
            debugID: stableID,
            isLocal: false)
    }

    @Test func `remembered gateway reconnects at moved service address without setup prompt`() async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let fence = GatewayDiscoverySelectionFence()
            let lease = fence.begin()
            let result = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: Self.gateway(),
                lease: lease,
                fence: fence,
                reconnect: { url, fingerprint in
                    #expect(url.absoluteString == "wss://moved-gateway.local:18790")
                    #expect(fingerprint == Self.fingerprint)
                    return AuthenticatedGatewayRoute(url: url, tlsFingerprint: fingerprint)
                },
                requestSetup: { _, _ in
                    Issue.record("A remembered Gateway should not need another setup code")
                    return nil
                },
                pair: { _ in
                    throw GatewayDiscoveryPairingError.invalidSetupCode
                })
            #expect(result?.url.absoluteString == "wss://moved-gateway.local:18790")
            #expect(result?.tlsFingerprint == Self.fingerprint)
            #expect(fence.isCurrent(lease))
        }
    }

    @Test(arguments: ["bonjour|new", "bonjour|previously-paired"])
    func `other discovery identities require setup even with a remembered pin`(stableID: String) async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let fence = GatewayDiscoverySelectionFence()
            let url = try #require(URL(string: "wss://setup-gateway.local:18789"))
            let replacement = String(repeating: "cd", count: 32)
            var prompted = false
            let result = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: Self.gateway(stableID: stableID),
                lease: fence.begin(),
                fence: fence,
                reconnect: { _, _ in
                    Issue.record("Another discovery identity cannot borrow the remembered pin")
                    throw GatewayDiscoveryPairingError.secureSetupRequired
                },
                requestSetup: { _, error in
                    #expect(error == nil)
                    prompted = true
                    return "fresh-setup"
                },
                pair: { input in
                    #expect(input == "fresh-setup")
                    return AuthenticatedGatewayRoute(url: url, tlsFingerprint: replacement)
                })
            #expect(prompted)
            #expect(result == AuthenticatedGatewayRoute(url: url, tlsFingerprint: replacement))
            #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == Self.fingerprint)
        }
    }

    @Test func `legacy preference and unresolved service cannot select a saved reconnect candidate`() async {
        await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            #expect(GatewayDiscoverySelectionSupport.savedReconnectCandidate(
                for: Self.gateway(serviceHost: nil)) == nil)
            GatewayDiscoveryPreferences.setPreferredStableID("bonjour|remembered")
            #expect(GatewayDiscoverySelectionSupport.savedReconnectCandidate(for: Self.gateway()) == nil)
        }
    }

    @Test func `failed reattach offers recovery and cancel preserves saved trust`() async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let fence = GatewayDiscoverySelectionFence()
            var prompted = false
            let result = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: Self.gateway(),
                lease: fence.begin(),
                fence: fence,
                reconnect: { _, _ in throw GatewayDiscoveryPairingError.savedDeviceCredentialUnavailable },
                requestSetup: { _, error in
                    #expect(error as? GatewayDiscoveryPairingError == .savedDeviceCredentialUnavailable)
                    prompted = true
                    return nil
                },
                pair: { _ in
                    Issue.record("Canceled recovery must not send a setup code")
                    throw GatewayDiscoveryPairingError.invalidSetupCode
                })
            #expect(prompted)
            #expect(result == nil)
            #expect(GatewayDiscoveryPreferences.preferredStableID() == "bonjour|remembered")
            #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == Self.fingerprint)
        }
    }

    @Test(arguments: [false, true])
    func `retired selection cannot prompt after a failed reconnect`(superseded: Bool) async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let fence = GatewayDiscoverySelectionFence()
            let result = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: Self.gateway(),
                lease: fence.begin(),
                fence: fence,
                reconnect: { _, _ in
                    if superseded { _ = fence.begin() } else { fence.invalidate() }
                    throw GatewayDiscoveryPairingError.savedDeviceCredentialUnavailable
                },
                requestSetup: { _, _ in
                    Issue.record("A retired selection must not show a late recovery prompt")
                    return nil
                })
            #expect(result == nil)
        }
    }

    @Test func `superseded successful reconnect cannot return a publishable route`() async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let fence = GatewayDiscoverySelectionFence()
            let result = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: Self.gateway(),
                lease: fence.begin(),
                fence: fence,
                reconnect: { url, fingerprint in
                    _ = fence.begin()
                    return AuthenticatedGatewayRoute(url: url, tlsFingerprint: fingerprint)
                },
                requestSetup: { _, _ in
                    Issue.record("A superseded reconnect must remain silent")
                    return nil
                })
            #expect(result == nil)
        }
    }

    @Test func `dismissal during setup modal prevents bootstrap dispatch`() async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let fence = GatewayDiscoverySelectionFence()
            let result = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: Self.gateway(stableID: "bonjour|new"),
                lease: fence.begin(),
                fence: fence,
                requestSetup: { _, _ in
                    fence.invalidate()
                    return "fresh-setup"
                },
                pair: { _ in
                    Issue.record("A dismissed selection must not dispatch bootstrap authentication")
                    throw GatewayDiscoveryPairingError.invalidSetupCode
                })
            #expect(result == nil)
        }
    }

    @Test func `superseded setup failure stays silent`() async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let fence = GatewayDiscoverySelectionFence()
            let result = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: Self.gateway(stableID: "bonjour|new"),
                lease: fence.begin(),
                fence: fence,
                requestSetup: { _, _ in "fresh-setup" },
                pair: { _ in
                    _ = fence.begin()
                    throw GatewayDiscoveryPairingError.invalidSetupCode
                })
            #expect(result == nil)
        }
    }

    @Test func `saved reconnect refuses plaintext before authentication`() async throws {
        let url = try #require(URL(string: "ws://127.0.0.1:18789"))
        await #expect(throws: GatewayDiscoveryPairingError.secureSetupRequired) {
            try await GatewayDiscoveryPairing.reconnect(url: url, tlsFingerprint: Self.fingerprint)
        }
    }

    @Test func `task cancellation during reconnect cannot prompt`() async throws {
        try await TestIsolation.withUserDefaultsValues(Self.preferenceDefaults) {
            let task = Task { @MainActor in
                let fence = GatewayDiscoverySelectionFence()
                return try await GatewayDiscoverySelectionSupport.authenticateSelection(
                    for: Self.gateway(),
                    lease: fence.begin(),
                    fence: fence,
                    reconnect: { _, _ in
                        withUnsafeCurrentTask { $0?.cancel() }
                        throw CancellationError()
                    },
                    requestSetup: { _, _ in
                        Issue.record("Canceled reconnect must remain silent")
                        return nil
                    })
            }
            #expect(try await task.value == nil)
        }
    }
}
