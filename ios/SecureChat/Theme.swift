import UIKit

/// The two page tokens the native chrome must match (client/style.css `bg` and
/// `fg`; android/app/src/main/res/values/colors.xml `app_bg` / `app_fg`), so
/// the bars and the page read as one surface.
enum Theme {
    static let bg = UIColor(red: 0x0D / 255, green: 0x11 / 255, blue: 0x17 / 255, alpha: 1)
    /// `--bg-top`: the page gradient starts here, so the bar above it uses it.
    static let bgTop = UIColor(red: 0x11 / 255, green: 0x16 / 255, blue: 0x1D / 255, alpha: 1)
    static let fg = UIColor(red: 0xD8 / 255, green: 0xDF / 255, blue: 0xE7 / 255, alpha: 1)
    static let accent = UIColor(red: 0x2F / 255, green: 0x81 / 255, blue: 0xF7 / 255, alpha: 1)
    static let muted = UIColor(red: 0x8B / 255, green: 0x94 / 255, blue: 0x9E / 255, alpha: 1)
}
