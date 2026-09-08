import Foundation

// periphery:ignore - Shipped identifier retained for compatibility tests after consumers stopped advertising it.
public enum OpenClawBrowserCommand: String, Codable, Sendable {
    case proxy = "browser.proxy"
}
