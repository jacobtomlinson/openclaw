import Foundation
import OpenClawDiscovery
import OpenClawKit
import Testing
@testable import OpenClaw

/// Opt-in proof that the macOS client crosses the real TLS Gateway boundary with route-owned credentials.
@Suite(.serialized)
@MainActor
struct GatewayDiscoveryPairingNativeProofTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["OPENCLAW_MACOS_GATEWAY_PAIRING_PROOF"] == "1"))
    func `mismatched discovery is denied before full access pairing and routed reconnects succeed`() async throws {
        let fixture = try await GatewayPairingNativeProofFixture.start()
        let outcome: Result<Void, Error>
        do {
            try await self.provePairingAndRevocation(fixture)
            try await self.proveCertificateRotation(fixture)
            outcome = .success(())
        } catch {
            outcome = .failure(error)
        }
        await fixture.stop()
        try outcome.get()
    }

    private func provePairingAndRevocation(_ fixture: GatewayPairingNativeProofFixture) async throws {
        let setupData = try JSONEncoder().encode(fixture.setup)
        var wrongSetup = try #require(JSONSerialization.jsonObject(with: setupData) as? [String: Any])
        let fingerprint = try #require(wrongSetup["tlsFingerprint"] as? String)
        let replacement = fingerprint.hasSuffix("0") ? "1" : "0"
        wrongSetup["tlsFingerprint"] = String(fingerprint.dropLast()) + replacement
        let wrongSetupData = try JSONSerialization.data(withJSONObject: wrongSetup)
        let wrongSetupInput = try #require(String(data: wrongSetupData, encoding: .utf8))

        do {
            _ = try await GatewayDiscoveryPairing.authenticate(setupInput: wrongSetupInput)
            Issue.record("A mismatched TLS discovery route reached Gateway authentication")
        } catch {
            #expect(error.localizedDescription.localizedCaseInsensitiveContains("certificate pin mismatch"))
            print("[pairing-proof] wrong certificate pin rejected before bootstrap authentication")
        }

        let setupInput = try #require(String(data: setupData, encoding: .utf8))
        var route = try await GatewayDiscoveryPairing.authenticate(setupInput: setupInput)
        #expect(route.tlsFingerprint == fingerprint.lowercased())

        let state = AppState(preview: true)
        state._testEnableGatewayConfigSync()
        state.remoteToken = "inherited-token-must-not-route"
        let fence = GatewayDiscoverySelectionFence()
        let supersededLease = fence.begin()
        let currentLease = fence.begin()
        let superseded = GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
            stableID: "bonjour|superseded-proof",
            route: route,
            state: state,
            lease: supersededLease,
            fence: fence)
        #expect(superseded == .superseded)
        #expect(GatewayDiscoveryPreferences.preferredStableID() == nil)
        #expect(state.remoteUrl != route.url.absoluteString)
        print("[pairing-proof] superseded selection rejected before route publication")

        let applied = GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
            stableID: "bonjour|native-proof",
            route: route,
            state: state,
            lease: currentLease,
            fence: fence)
        #expect(applied == .applied)
        #expect(GatewayDiscoveryPreferences.preferredStableID() == "bonjour|native-proof")
        print("[pairing-proof] current authenticated selection published")

        let discovered = GatewayDiscoveryModel.DiscoveredGateway(
            displayName: "Native proof Gateway",
            serviceHost: "localhost",
            servicePort: try #require(route.url.port),
            sshPort: 22,
            gatewayTls: false,
            stableID: "bonjour|native-proof",
            debugID: "native-proof",
            isLocal: false)
        let reconnectLease = fence.begin()
        let reattached = try await GatewayDiscoverySelectionSupport.authenticateSelection(
            for: discovered,
            lease: reconnectLease,
            fence: fence,
            requestSetup: { _, _ in
                Issue.record("A paired Gateway requested another setup code")
                return nil
            })
        route = try #require(reattached)
        #expect(route.url.host == "localhost")
        #expect(route.tlsFingerprint == fingerprint.lowercased())
        #expect(GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
            stableID: discovered.stableID,
            route: route,
            state: state,
            lease: reconnectLease,
            fence: fence) == .applied)
        print("[pairing-proof] moved discovered address reattached both roles without a setup code")

        let savedRoot = OpenClawConfigFile.loadDict()
        let savedURL = try #require(GatewayRemoteConfig.resolveTransportResolution(root: savedRoot).directURL)
        #expect(savedURL == route.url)
        #expect(GatewayRemoteConfig.resolveTLSFingerprint(root: savedRoot) == fingerprint.lowercased())
        let reconnectState = AppState(preview: true)
        #expect(reconnectState.connectionMode == .remote)
        #expect(reconnectState.remoteTransport == .direct)
        #expect(GatewayRemoteConfig.normalizeGatewayUrl(reconnectState.remoteUrl) == savedURL)
        #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == fingerprint.lowercased())
        reconnectState._testEnableGatewayConfigSync()

        let source = try await GatewayEndpointStore._testLiveSourceSnapshot(
            state: reconnectState,
            beforeConfigRead: {})
        #expect(source.token == nil)
        #expect(source.password == nil)
        let owner = try #require(source.deviceAuthGatewayID)
        #expect(owner == "tls-sha256:\(fingerprint.lowercased())")
        print("[pairing-proof] saved route withheld process-environment shared credentials")

        let identity = try #require(DeviceIdentityStore.loadOrCreatePersisted(profile: .primary))
        let wrongFingerprint = String(fingerprint.dropLast()) + replacement
        let wrongOwner = try #require(GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(wrongFingerprint))
        for role in ["operator", "node"] {
            #expect(DeviceAuthStore.storeTokenPersisted(
                deviceId: identity.deviceId,
                role: role,
                token: "must-not-cross-mismatched-tls",
                scopes: role == "operator" ? GatewayChannelActor.defaultOperatorConnectScopes : [],
                gatewayID: wrongOwner,
                profile: .primary))
        }
        do {
            _ = try await GatewayDiscoveryPairing.reconnect(url: savedURL, tlsFingerprint: wrongFingerprint)
            Issue.record("Stored device credentials crossed a mismatched certificate pin")
        } catch {
            #expect(error.localizedDescription.localizedCaseInsensitiveContains("certificate pin mismatch"))
        }
        #expect(DeviceAuthStore.clearGatewayTokensPersisted(
            deviceId: identity.deviceId,
            gatewayID: wrongOwner,
            profile: .primary))
        print("[pairing-proof] saved device credentials rejected before mismatched TLS admission")

        for role in ["operator", "node"] {
            let credential = try #require(DeviceAuthStore.loadToken(
                deviceId: identity.deviceId,
                role: role,
                gatewayID: owner,
                profile: .primary))
            DeviceAuthStore.clearToken(
                deviceId: identity.deviceId,
                role: role,
                gatewayID: owner,
                profile: .primary)
            try await self.expectSetupRecovery(for: discovered, state: reconnectState)
            #expect(DeviceAuthStore.storeTokenPersisted(
                deviceId: identity.deviceId,
                role: role,
                token: credential.token,
                scopes: credential.scopes,
                gatewayID: owner,
                profile: .primary))
            print("[pairing-proof] missing \(role) credential required setup recovery without route publication")
        }

        let endpoint = GatewayConnection.EndpointSnapshot(
            config: (savedURL, source.token, source.password),
            tls: GatewayTLSRoute.resolve(
                url: savedURL,
                connectionMode: .remote,
                configuredFingerprint: source.remoteTLSFingerprint),
            routeAuthority: nil,
            deviceAuthGatewayID: owner)
        try await self.proveTransportIsolation(fixture, fingerprint: fingerprint)

        let operatorConnection = GatewayConnection(endpointProvider: { endpoint }, supportsSharedEndpointRecovery: false)
        defer { Task { await operatorConnection.shutdown() } }
        _ = try await operatorConnection.request(method: "health", params: nil, timeoutMs: 15_000)
        #expect(await operatorConnection.authSource() == .deviceToken)
        print("[pairing-proof] saved-route operator reconnect used fingerprint-owned device auth")

        let nodeClient = GatewayPairingNativeProofNode()
        defer { Task { await nodeClient.disconnect() } }
        try await nodeClient.connect(endpoint)
        #expect(nodeClient.admissions == 1)
        print("[pairing-proof] saved-route node reconnect used the production TLS cache and node session")

        _ = try await operatorConnection.request(
            method: "device.token.revoke",
            params: [
                "deviceId": AnyCodable(identity.deviceId),
                "role": AnyCodable("node"),
            ],
            timeoutMs: 15_000)
        try await self.expectSetupRecovery(for: discovered, state: reconnectState)
        print("[pairing-proof] revoked node role required setup recovery before publication")
        _ = try await operatorConnection.request(
            method: "device.token.revoke",
            params: [
                "deviceId": AnyCodable(identity.deviceId),
                "role": AnyCodable("operator"),
            ],
            timeoutMs: 15_000)
        try await self.expectSetupRecovery(for: discovered, state: reconnectState)
        print("[pairing-proof] revoked operator role required setup recovery before publication")
        await operatorConnection.shutdown()
        await nodeClient.disconnect()
        print("[pairing-proof] Gateway revoked both fingerprint-owned device roles")

        var plaintextComponents = try #require(URLComponents(url: savedURL, resolvingAgainstBaseURL: false))
        plaintextComponents.scheme = "ws"
        let plaintextURL = try #require(plaintextComponents.url)
        reconnectState.remoteUrl = plaintextURL.absoluteString
        #expect(reconnectState.syncGatewayConfigNow())
        let committedPlaintextURL = GatewayRemoteConfig.resolveTransportResolution(
            root: OpenClawConfigFile.loadDict()).directURL
        #expect(committedPlaintextURL == plaintextURL)
        let plaintextSource = try await GatewayEndpointStore._testLiveSourceSnapshot(
            state: reconnectState,
            beforeConfigRead: {})
        let plaintextOwner = try #require(plaintextSource.deviceAuthGatewayID)
        #expect(!plaintextOwner.hasPrefix("tls-sha256:"))
        #expect(GatewayDiscoveryPreferences.admittedDeviceAuthGatewayID(
            "tls-sha256:\(fingerprint.lowercased())",
            tls: nil) == nil)
        print("[pairing-proof] plaintext downgrade rejected certificate-owned credentials")

        let revokedOperator = GatewayConnection(endpointProvider: { endpoint }, supportsSharedEndpointRecovery: false)
        defer { Task { await revokedOperator.shutdown() } }
        do {
            _ = try await revokedOperator.request(method: "health", params: nil, timeoutMs: 15_000)
            Issue.record("Revoked operator authority reached a protected Gateway method")
        } catch {
            #expect(await revokedOperator.authSource() == GatewayAuthSource.deviceToken)
            print("[pairing-proof] revoked operator authority rejected before protected health RPC")
        }

        await revokedOperator.shutdown()

        let revokedNode = GatewayPairingNativeProofNode()
        let revokedNodeToken = try #require(DeviceAuthStore.loadToken(
            deviceId: identity.deviceId, role: "node", gatewayID: owner, profile: .primary)).token
        try await fixture.command("mode", fields: ["mode": "normal"])
        do {
            try await revokedNode.connect(endpoint)
            Issue.record("Revoked node authority established a Gateway connection")
        } catch {
            #expect(revokedNode.admissions == 0)
            #expect(await revokedNode.session.currentRoute() == nil)
            let observed = try await fixture.command("snapshot")
            #expect(observed.connects.contains { $0.role == "node" && $0.auth["token"] == revokedNodeToken })
            print("[pairing-proof] revoked node authority rejected before connection admission")
        }
        await revokedNode.disconnect()
    }

    private func expectSetupRecovery(
        for gateway: GatewayDiscoveryModel.DiscoveredGateway,
        state: AppState) async throws
    {
        let previousURL = state.remoteUrl
        let previousConfig = OpenClawConfigFile.loadDict() as NSDictionary
        let previousFingerprint = GatewayDiscoveryPreferences.authenticatedTLSFingerprint()
        let fence = GatewayDiscoverySelectionFence()
        var prompted = false
        let route = try await GatewayDiscoverySelectionSupport.authenticateSelection(
            for: gateway,
            lease: fence.begin(),
            fence: fence,
            requestSetup: { _, error in
                #expect(error != nil)
                prompted = true
                return nil
            })
        #expect(prompted)
        #expect(route == nil)
        #expect(state.remoteUrl == previousURL)
        #expect(OpenClawConfigFile.loadDict() as NSDictionary == previousConfig)
        #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == previousFingerprint)
    }
}
