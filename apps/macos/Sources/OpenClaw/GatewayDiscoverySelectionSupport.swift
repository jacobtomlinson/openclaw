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
    static func requestSetupCode(for gateway: GatewayDiscoveryModel.DiscoveredGateway) -> String? {
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        field.placeholderString = "Paste the setup code from this Gateway"
        field.setAccessibilityLabel("Gateway setup code")

        let alert = NSAlert()
        alert.messageText = "Authenticate \(gateway.displayName)"
        alert.informativeText =
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
