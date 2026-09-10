import Foundation
import OpenClawDiscovery
import OpenClawKit
import Testing
@testable import OpenClaw

extension GatewayDiscoveryPairingNativeProofTests {
    func proveCertificateRotation(_ fixture: GatewayPairingNativeProofFixture) async throws {
        try await fixture.command("mode", fields: ["mode": "normal"])
        let setupA = try await fixture.command("setup").setup
        let routeA = try await GatewayDiscoveryPairing.authenticate(setupInput: setupA.input)
        let ownerA = try #require(GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(routeA.tlsFingerprint))
        let identity = try #require(DeviceIdentityStore.loadOrCreatePersisted(profile: .primary))
        let fence = GatewayDiscoverySelectionFence()
        let stableID = "bonjour|native-rotation-proof"
        let stateA = AppState(preview: true)
        stateA._testEnableGatewayConfigSync()
        #expect(GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
            stableID: stableID, route: routeA, state: stateA, lease: fence.begin(), fence: fence) == .applied)
        let oldTokens = try self.proofTokens(fingerprint: routeA.tlsFingerprint)
        let oldConfig = OpenClawConfigFile.loadDict() as NSDictionary

        let rotated = try await fixture.command("rotate")
        var setupB = rotated.setup
        #expect(setupB.url == setupA.url)
        #expect(setupB.tlsFingerprint != setupA.tlsFingerprint)
        let ownerB = try #require(GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(setupB.tlsFingerprint))
        #expect(ownerB != ownerA)
        // Change the resolved spelling as well as the certificate: publication must commit the URL/pin bundle.
        var moved = try #require(URLComponents(url: setupB.url, resolvingAgainstBaseURL: false))
        moved.host = "localhost"
        setupB.url = try #require(moved.url)
        let discovered = GatewayDiscoveryModel.DiscoveredGateway(
            displayName: "Rotated native proof Gateway", serviceHost: "localhost",
            servicePort: try #require(setupB.url.port), sshPort: 22, gatewayTls: true,
            stableID: stableID, debugID: "native-rotation-proof", isLocal: false)

        do {
            _ = try await GatewayDiscoveryPairing.reconnect(url: setupB.url, tlsFingerprint: routeA.tlsFingerprint)
            Issue.record("Saved certificate A accepted rotated certificate B")
        } catch {
            #expect(error.localizedDescription.localizedCaseInsensitiveContains("certificate pin mismatch"))
        }
        let rejected = try await fixture.command("snapshot")
        #expect((rejected.tlsConnections["primary"] ?? 0) > 0)
        #expect(rejected.requests.isEmpty)
        #expect(rejected.connects.isEmpty)
        self.expectRotationPreserved(stateA, route: routeA, stableID: stableID, config: oldConfig)

        var cancelPrompts = 0
        let cancelled = try await GatewayDiscoverySelectionSupport.authenticateSelection(
            for: discovered, lease: fence.begin(), fence: fence,
            requestSetup: { _, error in
                #expect(error != nil)
                cancelPrompts += 1
                return nil
            })
        #expect(cancelPrompts == 1)
        #expect(cancelled == nil)
        self.expectRotationPreserved(stateA, route: routeA, stableID: stableID, config: oldConfig)

        var invalidSetup = setupB
        invalidSetup.bootstrapToken = "invalid-native-proof-bootstrap"
        let invalidInput = try invalidSetup.input
        var invalidPrompts = 0
        try await fixture.command("mode", fields: ["mode": "normal"])
        do {
            _ = try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: discovered, lease: fence.begin(), fence: fence,
                requestSetup: { _, error in
                    #expect(error != nil)
                    invalidPrompts += 1
                    return invalidInput
                })
            Issue.record("An invalid fresh setup code recovered rotated trust")
        } catch {
            #expect(error as? GatewayDiscoveryPairingError == .invalidSetupCode)
        }
        #expect(invalidPrompts == 1)
        let invalid = try await fixture.command("snapshot")
        #expect(invalid.connects.count == 1)
        #expect(invalid.connects.first?.auth == ["bootstrapToken": invalidSetup.bootstrapToken])
        self.expectRotationPreserved(stateA, route: routeA, stableID: stableID, config: oldConfig)
        for role in ["operator", "node"] {
            #expect(DeviceAuthStore.loadToken(
                deviceId: identity.deviceId, role: role, gatewayID: ownerB, profile: .primary) == nil)
        }

        try await self.completeRotation(
            fixture, setup: setupB, oldRoute: routeA, oldConfig: oldConfig,
            oldTokens: oldTokens, discovered: discovered, identity: identity)
        print("[pairing-proof] certificate A-to-B recovery persisted both roles before atomic publication")
    }

    private func completeRotation(
        _ fixture: GatewayPairingNativeProofFixture,
        setup: GatewayPairingNativeProofFixture.Setup,
        oldRoute: AuthenticatedGatewayRoute,
        oldConfig: NSDictionary,
        oldTokens: [String: String],
        discovered: GatewayDiscoveryModel.DiscoveredGateway,
        identity: DeviceIdentity) async throws
    {
        let owner = try #require(GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(setup.tlsFingerprint))
        let fence = GatewayDiscoverySelectionFence()
        let lease = fence.begin()
        let setupInput = try setup.input
        var prompts = 0
        var saves: [[String: Any]] = []
        var publicationState: AppState?
        let state = AppState(preview: true, gatewayConfigSaver: { root, allowModeRemoval in
            // Observe the existing persistence owner at its single commit boundary, then use the real saver.
            #expect(OpenClawConfigFile.loadDict() as NSDictionary == oldConfig)
            #expect(publicationState?.remoteUrl == oldRoute.url.absoluteString)
            #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == setup.tlsFingerprint.lowercased())
            let tokens = try? self.proofTokens(fingerprint: setup.tlsFingerprint)
            #expect(tokens?.count == 2)
            let remote = (root["gateway"] as? [String: Any])?["remote"] as? [String: Any]
            #expect(remote?["url"] as? String == setup.url.absoluteString)
            #expect(remote?["tlsFingerprint"] as? String == setup.tlsFingerprint.lowercased())
            #expect(remote?["token"] == nil)
            #expect(remote?["password"] == nil)
            saves.append(root)
            return OpenClawConfigFile.saveDict(root, allowGatewayModeRemoval: allowModeRemoval)
        })
        publicationState = state
        state._testEnableGatewayConfigSync()
        try await fixture.command("mode", fields: ["mode": "barrier"])
        let pending = Task {
            try await GatewayDiscoverySelectionSupport.authenticateSelection(
                for: discovered, lease: lease, fence: fence,
                requestSetup: { _, error in
                    #expect(error != nil)
                    prompts += 1
                    return setupInput
                })
        }
        let authenticated: AuthenticatedGatewayRoute
        do {
            let held = try await fixture.waitForBarrier()
            #expect(held.connects.count == 1)
            #expect(held.connects.first?.auth == ["bootstrapToken": setup.bootstrapToken])
            #expect(prompts == 1)
            #expect(saves.isEmpty)
            self.expectRotationPreserved(state, route: oldRoute, stableID: discovered.stableID, config: oldConfig)
            for role in ["operator", "node"] {
                #expect(DeviceAuthStore.loadToken(
                    deviceId: identity.deviceId, role: role, gatewayID: owner, profile: .primary) == nil)
            }
            try await fixture.command("release")
            let result = try await pending.value
            authenticated = try #require(result)
        } catch {
            pending.cancel()
            _ = try? await fixture.command("release")
            _ = await pending.result
            throw error
        }
        #expect(authenticated.url == setup.url)
        #expect(authenticated.tlsFingerprint == setup.tlsFingerprint.lowercased())
        let newTokens = try self.proofTokens(fingerprint: setup.tlsFingerprint)
        self.expectRotationPreserved(state, route: oldRoute, stableID: discovered.stableID, config: oldConfig)
        #expect(saves.isEmpty)
        #expect(try self.proofTokens(fingerprint: oldRoute.tlsFingerprint) == oldTokens)

        // Full-access issuance must be usable as both roles before publishing the new URL/pin.
        try await fixture.command("mode", fields: ["mode": "normal"])
        let checked = try await GatewayDiscoveryPairing.reconnect(
            url: authenticated.url, tlsFingerprint: authenticated.tlsFingerprint)
        #expect(checked == authenticated)
        let precommit = try await fixture.command("snapshot")
        self.expectDeviceFrames(precommit, roles: ["operator", "node"], tokens: newTokens)
        #expect(saves.isEmpty)
        #expect(GatewayDiscoverySelectionSupport.applyAuthenticatedSelection(
            stableID: discovered.stableID, route: authenticated, state: state, lease: lease, fence: fence) == .applied)
        #expect(saves.count == 1)
        #expect(state.remoteUrl == setup.url.absoluteString)
        #expect(GatewayRemoteConfig.resolveTransportResolution(root: OpenClawConfigFile.loadDict()).directURL == setup.url)
        #expect(GatewayRemoteConfig.resolveTLSFingerprint(root: OpenClawConfigFile.loadDict()) ==
            setup.tlsFingerprint.lowercased())
        #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == setup.tlsFingerprint.lowercased())
        publicationState = nil

        // Distinguish credential owners even if the Gateway reissued the same token bytes at rotation.
        // The obsolete owner remains populated, but its synthetic decoys cannot authenticate at B.
        let obsoleteOwner = try #require(GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(oldRoute.tlsFingerprint))
        for role in ["operator", "node"] {
            let oldEntry = try #require(DeviceAuthStore.loadToken(
                deviceId: identity.deviceId, role: role, gatewayID: obsoleteOwner, profile: .primary))
            #expect(DeviceAuthStore.storeTokenPersisted(
                deviceId: identity.deviceId, role: role, token: "obsolete-owner-must-not-route-\(role)",
                scopes: oldEntry.scopes, gatewayID: obsoleteOwner, profile: .primary))
        }
        try await fixture.command("mode", fields: ["mode": "normal"])
        let reconnectFence = GatewayDiscoverySelectionFence()
        let noCode = try await GatewayDiscoverySelectionSupport.authenticateSelection(
            for: discovered, lease: reconnectFence.begin(), fence: reconnectFence,
            requestSetup: { _, _ in
                Issue.record("Recovered certificate B requested another setup code")
                return nil
            })
        #expect(noCode == authenticated)
        let reattached = try await fixture.command("snapshot")
        self.expectDeviceFrames(reattached, roles: ["operator", "node"], tokens: newTokens)
        let source = try await GatewayEndpointStore._testLiveSourceSnapshot(state: state, beforeConfigRead: {})
        #expect(source.deviceAuthGatewayID == owner)
        #expect(source.token == nil)
        #expect(source.password == nil)
        print("[pairing-proof] recovered Gateway reattached without a setup prompt using certificate B device tokens")
    }

    private func expectRotationPreserved(
        _ state: AppState,
        route: AuthenticatedGatewayRoute,
        stableID: String,
        config: NSDictionary)
    {
        #expect(state.remoteUrl == route.url.absoluteString)
        #expect(OpenClawConfigFile.loadDict() as NSDictionary == config)
        #expect(GatewayDiscoveryPreferences.preferredStableID() == stableID)
        #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == route.tlsFingerprint)
    }
}
