import Foundation
import OpenClawKit
import Testing
@testable import OpenClaw

extension GatewayDiscoveryPairingNativeProofTests {
    private enum TransportClient: String, CaseIterable {
        case pairing, reattach, `operator`, node

        var roles: [String] {
            switch self {
            case .pairing, .node: ["node"]
            case .reattach: ["operator", "node"]
            case .operator: ["operator"]
            }
        }
    }

    func proveTransportIsolation(_ fixture: GatewayPairingNativeProofFixture, fingerprint: String) async throws {
        let initialConfig = OpenClawConfigFile.loadDict() as NSDictionary
        let initialTrust = GatewayDiscoveryPreferences.authenticatedTLSFingerprint()
        let node = GatewayPairingNativeProofNode()
        let pinStoreKey = GatewayTLSRoute.storeKey(for: fixture.setup.url)
        let storedPin = GatewayTLSStore.loadFingerprint(stableID: pinStoreKey)
        // Every factory first proves real authentication. The repeated cookie controls also exercise
        // response-cookie replay on new sessions and on the production node cache's reused session.
        for client in TransportClient.allCases {
            try await self.proveCookieIsolation(client, fixture: fixture, node: node, fingerprint: fingerprint)
            for target in ["host", "port", "path", "plaintext"] {
                for status in [302, 307] {
                    let setup = try await fixture.command("setup").setup
                    try await fixture.command("mode", fields: [
                        "mode": "redirect", "target": target, "status": status,
                    ])
                    let outcome = await self.exerciseTransportClient(client, setup: setup, node: node)
                    self.expectTransportFailure(outcome, context: "\(client.rawValue), \(status), \(target)")
                    let observed = try await fixture.command("snapshot")
                    #expect(!observed.requests.isEmpty)
                    #expect(observed.requests.allSatisfy { $0.endpoint == "primary" && $0.path == "/" })
                    #expect(observed.connects.isEmpty)
                    print("[pairing-proof] \(client.rawValue) denied \(status) redirect to \(target)")
                }
            }
            let setup = try await fixture.command("setup").setup
            try await fixture.command("mode", fields: ["mode": "wrongCertificate"])
            let outcome = await self.exerciseTransportClient(client, setup: setup, node: node)
            self.expectTransportFailure(outcome, context: "\(client.rawValue), wrong certificate")
            let observed = try await fixture.command("snapshot")
            #expect((observed.tlsConnections["primary"] ?? 0) > 0)
            #expect(observed.requests.isEmpty)
            #expect(observed.connects.isEmpty)
            #expect(GatewayTLSStore.loadFingerprint(stableID: pinStoreKey) == storedPin)
        }

        // A successful operator must not make the following node socket inherit redirect authority.
        let setup = try await fixture.command("setup").setup
        let tokens = try self.proofTokens(fingerprint: fingerprint)
        try await fixture.command("mode", fields: [
            "mode": "redirect", "target": "port", "status": 307, "afterUpgrades": 1,
        ])
        let outcome = await self.exerciseTransportClient(.reattach, setup: setup, node: node)
        self.expectTransportFailure(outcome, context: "node redirect after accepted operator")
        let observed = try await fixture.command("snapshot")
        #expect(observed.requests.count >= 2)
        #expect(observed.requests.allSatisfy { $0.endpoint == "primary" })
        #expect(observed.connects.count == 1)
        self.expectDeviceFrames(observed, roles: ["operator"], tokens: tokens)
        try await fixture.command("mode", fields: ["mode": "normal"])
        #expect(OpenClawConfigFile.loadDict() as NSDictionary == initialConfig)
        #expect(GatewayDiscoveryPreferences.authenticatedTLSFingerprint() == initialTrust)
    }

    private func proveCookieIsolation(
        _ client: TransportClient,
        fixture: GatewayPairingNativeProofFixture,
        node: GatewayPairingNativeProofNode,
        fingerprint: String) async throws
    {
        let url = fixture.setup.url
        var origin = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
        origin.scheme = "https"
        let httpURL = try #require(origin.url)
        let prefix = "native-proof-\(UUID().uuidString)"
        let responseName = "\(prefix)-response"
        let cookie = try #require(HTTPCookie(properties: [
            .name: prefix, .value: "ambient-account", .originURL: httpURL, .path: "/", .secure: "TRUE",
        ]))
        let space = URLProtectionSpace(
            host: try #require(httpURL.host), port: try #require(httpURL.port), protocol: "https",
            realm: "native-proof", authenticationMethod: NSURLAuthenticationMethodHTTPBasic)
        let credential = URLCredential(user: prefix, password: "ambient-password", persistence: .forSession)
        let previousDefault = URLCredentialStorage.shared.defaultCredential(for: space)
        HTTPCookieStorage.shared.setCookie(cookie)
        URLCredentialStorage.shared.setDefaultCredential(credential, for: space)
        #expect(HTTPCookieStorage.shared.cookies(for: httpURL)?.contains { $0.name == prefix } == true)
        #expect(URLCredentialStorage.shared.defaultCredential(for: space)?.user == prefix)
        defer {
            for stored in HTTPCookieStorage.shared.cookies ?? [] where stored.name.hasPrefix(prefix) {
                HTTPCookieStorage.shared.deleteCookie(stored)
            }
            URLCredentialStorage.shared.remove(credential, for: space)
            if let previousDefault { URLCredentialStorage.shared.setDefaultCredential(previousDefault, for: space) }
        }

        try await fixture.command("mode", fields: ["mode": "cookie", "cookieName": responseName])
        var previousNodeTransport: ObjectIdentifier?
        for attempt in 0..<2 {
            let setup = try await fixture.command("setup").setup
            let tokens = try self.proofTokens(fingerprint: fingerprint)
            let outcome = await self.exerciseTransportClient(client, setup: setup, node: node)
            try outcome.get()
            let observed = try await fixture.command("snapshot")
            #expect(!observed.requests.isEmpty)
            self.expectNoHTTPIdentity(observed, cookiePrefix: prefix)
            let expectedRoles = Array(repeating: client.roles, count: attempt + 1).flatMap { $0 }
            if client == .pairing {
                #expect(observed.connects.map(\.role) == expectedRoles.map(Optional.some))
                #expect(observed.connects.last?.auth == ["bootstrapToken": setup.bootstrapToken])
                _ = try self.proofTokens(fingerprint: fingerprint)
            } else {
                self.expectDeviceFrames(observed, roles: expectedRoles, tokens: tokens)
            }
            if client == .node {
                if let previousNodeTransport { #expect(node.transportIdentity == previousNodeTransport) }
                previousNodeTransport = node.transportIdentity
            }
        }

        let setup = try await fixture.command("setup").setup
        try await fixture.command("mode", fields: ["mode": "challenge", "cookieName": responseName])
        let denied = await self.exerciseTransportClient(client, setup: setup, node: node)
        self.expectTransportFailure(denied, context: "\(client.rawValue), ambient HTTP Basic challenge")
        let challenged = try await fixture.command("snapshot")
        #expect(!challenged.requests.isEmpty)
        #expect(challenged.connects.isEmpty)
        self.expectNoHTTPIdentity(challenged, cookiePrefix: prefix)

        // Check replay after both a successful 101 Set-Cookie and a rejected 401 Set-Cookie.
        try await fixture.command("mode", fields: ["mode": "normal"])
        let freshSetup = try await fixture.command("setup").setup
        let tokens = try self.proofTokens(fingerprint: fingerprint)
        let recovered = await self.exerciseTransportClient(client, setup: freshSetup, node: node)
        try recovered.get()
        let observed = try await fixture.command("snapshot")
        self.expectNoHTTPIdentity(observed, cookiePrefix: prefix)
        if client == .pairing {
            #expect(observed.connects.count == 1)
            #expect(observed.connects.first?.auth == ["bootstrapToken": freshSetup.bootstrapToken])
        } else {
            self.expectDeviceFrames(observed, roles: client.roles, tokens: tokens)
        }
        print("[pairing-proof] \(client.rawValue) isolated ambient HTTP identity and response-cookie replay")
    }

    private func expectNoHTTPIdentity(
        _ observed: GatewayPairingNativeProofFixture.Observation,
        cookiePrefix: String)
    {
        #expect(observed.requests.allSatisfy { $0.headers["cookie"] == nil && $0.headers["authorization"] == nil })
        #expect(HTTPCookieStorage.shared.cookies?.contains { $0.name == "\(cookiePrefix)-response" } != true)
    }

    private func exerciseTransportClient(
        _ client: TransportClient,
        setup: GatewayPairingNativeProofFixture.Setup,
        node: GatewayPairingNativeProofNode) async -> Result<Void, Error>
    {
        let endpoint = self.proofEndpoint(url: setup.url, fingerprint: setup.tlsFingerprint)
        #expect(endpoint.tls?.allowsTrustedPinReplacement == false)
        #expect(endpoint.tls?.params.allowTOFU == false)
        let connection = GatewayConnection(endpointProvider: { endpoint }, supportsSharedEndpointRecovery: false)
        let admissions = node.admissions
        let outcome: Result<Void, Error>
        do {
            switch client {
            case .pairing:
                let route = try await GatewayDiscoveryPairing.authenticate(setupInput: setup.input)
                #expect(route.url == setup.url)
                #expect(route.tlsFingerprint == setup.tlsFingerprint.lowercased())
            case .reattach:
                let route = try await GatewayDiscoveryPairing.reconnect(
                    url: setup.url, tlsFingerprint: setup.tlsFingerprint)
                #expect(route.url == setup.url)
            case .operator:
                _ = try await connection.request(method: "health", params: nil, timeoutMs: 10_000, retryTransportFailures: false)
                #expect(await connection.authSource() == .deviceToken)
            case .node:
                try await node.connect(endpoint)
                #expect(node.admissions == admissions + 1)
            }
            outcome = .success(())
        } catch {
            if client == .node {
                #expect(node.admissions == admissions)
                #expect(await node.session.currentRoute() == nil)
            }
            outcome = .failure(error)
        }
        await connection.shutdown()
        await node.disconnect()
        return outcome
    }

    private func expectTransportFailure(_ outcome: Result<Void, Error>, context: String) {
        if case .success = outcome { Issue.record("Transport unexpectedly authenticated: \(context)") }
    }

    func proofEndpoint(url: URL, fingerprint: String) -> GatewayConnection.EndpointSnapshot {
        GatewayConnection.EndpointSnapshot(
            config: (url, nil, nil),
            tls: GatewayTLSRoute.resolve(url: url, connectionMode: .remote, configuredFingerprint: fingerprint),
            routeAuthority: nil,
            deviceAuthGatewayID: GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(fingerprint))
    }

    func proofTokens(fingerprint: String) throws -> [String: String] {
        let owner = try #require(GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(fingerprint))
        let identity = try #require(DeviceIdentityStore.loadOrCreatePersisted(profile: .primary))
        var tokens: [String: String] = [:]
        for role in ["operator", "node"] {
            let entry = try #require(DeviceAuthStore.loadToken(
                deviceId: identity.deviceId, role: role, gatewayID: owner, profile: .primary))
            #expect(!entry.token.isEmpty)
            tokens[role] = entry.token
        }
        return tokens
    }

    func expectDeviceFrames(
        _ observed: GatewayPairingNativeProofFixture.Observation,
        roles: [String],
        tokens: [String: String])
    {
        #expect(observed.connects.map(\.role) == roles.map(Optional.some))
        for frame in observed.connects {
            let role = frame.role ?? ""
            #expect(frame.endpoint == "primary")
            #expect(frame.auth == ["token": tokens[role] ?? "missing-role-token"])
        }
    }
}
