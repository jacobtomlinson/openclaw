import AppKit
import Foundation
import OpenClawDiscovery

@MainActor
final class GatewayDiscoverySelectionFence {
    struct Lease: Equatable {
        fileprivate let id: UUID
    }

    private var activeLease: Lease?

    func begin() -> Lease {
        let lease = Lease(id: UUID())
        self.activeLease = lease
        return lease
    }

    @discardableResult
    func invalidate() -> Bool {
        let hadActiveLease = self.activeLease != nil
        self.activeLease = nil
        return hadActiveLease
    }

    func isCurrent(_ lease: Lease) -> Bool {
        self.activeLease == lease
    }

    func consume(_ lease: Lease) -> Bool {
        guard self.activeLease == lease else { return false }
        self.activeLease = nil
        return true
    }
}

enum GatewayDiscoverySelectionApplyResult: Equatable {
    case applied
    case superseded
    case saveFailed
}

@MainActor
enum GatewayDiscoverySelectionSupport {
    /// There is one saved discovery identity, not a trust registry. A matching
    /// discovery id only selects the saved pin to try; it never authenticates the
    /// advertised address. Ignore advertised TLS metadata and always require WSS.
    static func savedReconnectCandidate(
        for gateway: GatewayDiscoveryModel.DiscoveredGateway) -> (url: URL, tlsFingerprint: String)?
    {
        guard gateway.stableID == GatewayDiscoveryPreferences.preferredStableID(),
              let fingerprint = GatewayDiscoveryPreferences.authenticatedTLSFingerprint(),
              let address = GatewayDiscoveryHelpers.directGatewayUrl(
                  serviceHost: gateway.serviceHost,
                  servicePort: gateway.servicePort,
                  gatewayTls: true),
              let url = URL(string: address), url.scheme?.lowercased() == "wss"
        else { return nil }
        return (url, fingerprint)
    }

    /// Both nearby-selection entry points share reconnect, recovery, and prompt
    /// fencing. No route is published until the caller consumes this same lease.
    static func authenticateSelection(
        for gateway: GatewayDiscoveryModel.DiscoveredGateway,
        lease: GatewayDiscoverySelectionFence.Lease,
        fence: GatewayDiscoverySelectionFence,
        reconnect: @MainActor (URL, String) async throws -> AuthenticatedGatewayRoute = {
            try await GatewayDiscoveryPairing.reconnect(url: $0, tlsFingerprint: $1)
        },
        requestSetup: @MainActor (GatewayDiscoveryModel.DiscoveredGateway, Error?) -> String? = {
            GatewayDiscoverySelectionSupport.requestSetupCode(for: $0, reconnectError: $1)
        },
        pair: @MainActor (String) async throws -> AuthenticatedGatewayRoute = {
            try await GatewayDiscoveryPairing.authenticate(setupInput: $0)
        }) async throws -> AuthenticatedGatewayRoute?
    {
        guard fence.isCurrent(lease), !Task.isCancelled else { return nil }
        var reconnectError: Error?
        if let candidate = self.savedReconnectCandidate(for: gateway) {
            do {
                let route = try await reconnect(candidate.url, candidate.tlsFingerprint)
                guard fence.isCurrent(lease), !Task.isCancelled else { return nil }
                return route
            } catch {
                reconnectError = error
            }
        }
        guard fence.isCurrent(lease), !Task.isCancelled else { return nil }
        let setupInput = requestSetup(gateway, reconnectError)
        // A modal prompt pumps the main run loop: dismissal or a newer selection
        // can invalidate the lease while it is open, too.
        guard fence.isCurrent(lease), !Task.isCancelled, let setupInput else { return nil }
        do {
            let route = try await pair(setupInput)
            guard fence.isCurrent(lease), !Task.isCancelled else { return nil }
            return route
        } catch {
            guard fence.isCurrent(lease), !Task.isCancelled else { return nil }
            throw error
        }
    }

    static func requestSetupCode(
        for gateway: GatewayDiscoveryModel.DiscoveredGateway,
        reconnectError: Error? = nil) -> String?
    {
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        field.placeholderString = "Paste the setup code from this Gateway"
        field.setAccessibilityLabel("Gateway setup code")

        let alert = NSAlert()
        alert.messageText = "Authenticate \(gateway.displayName)"
        let recovery = reconnectError.map {
            "The saved pairing could not reconnect: \($0.localizedDescription) " +
                "Check that the Gateway is reachable, or pair again with a fresh setup code.\n\n"
        } ?? ""
        alert.informativeText = recovery +
            "Bonjour can locate a Gateway, but cannot prove its identity. " +
            "On that Gateway, open Control UI → Settings → Devices → Pair device, keep Full access, " +
            "and create a setup code. " +
            "OpenClaw will verify its TLS certificate before sending the one-time bootstrap credential."
        alert.alertStyle = .informational
        alert.accessoryView = field
        alert.addButton(withTitle: "Authenticate")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return field.stringValue
    }

    static func presentError(_ error: Error) {
        let alert = NSAlert()
        alert.messageText = "Could Not Authenticate Gateway"
        alert.informativeText = error.localizedDescription
        alert.alertStyle = .warning
        alert.runModal()
    }

    static func applyAuthenticatedSelection(
        stableID: String,
        route: AuthenticatedGatewayRoute,
        state: AppState,
        lease: GatewayDiscoverySelectionFence.Lease,
        fence: GatewayDiscoverySelectionFence) -> GatewayDiscoverySelectionApplyResult
    {
        // Consuming the current user-intent lease is the final synchronous gate
        // before this authenticated route can become observable to either client.
        guard fence.consume(lease) else { return .superseded }
        guard GatewayDiscoveryPreferences.tlsDeviceAuthGatewayID(route.tlsFingerprint) != nil else {
            return .saveFailed
        }
        let previousPreference = (
            stableID: GatewayDiscoveryPreferences.preferredStableID(),
            routeBinding: GatewayDiscoveryPreferences.preferredRouteBinding(),
            tlsFingerprint: GatewayDiscoveryPreferences.authenticatedTLSFingerprint())

        // Publish trust before the replacement can become observable. The AppState
        // owner commits the URL, fingerprint, and removal of shared auth atomically.
        GatewayDiscoveryPreferences.setAuthenticatedPreferredGateway(
            stableID: stableID,
            tlsFingerprint: route.tlsFingerprint)
        let replacement = AppState.PrimaryGatewayConfiguration(
            url: route.url,
            token: nil,
            tlsFingerprint: route.tlsFingerprint)
        guard state.replacePrimaryGateway(replacement) else {
            if let stableID = previousPreference.stableID,
               let fingerprint = previousPreference.tlsFingerprint
            {
                GatewayDiscoveryPreferences.setAuthenticatedPreferredGateway(
                    stableID: stableID,
                    tlsFingerprint: fingerprint)
            } else {
                GatewayDiscoveryPreferences.setPreferredStableID(
                    previousPreference.stableID,
                    routeBinding: previousPreference.routeBinding)
            }
            return .saveFailed
        }
        MacNodeModeCoordinator.shared.refresh()
        return .applied
    }
}
