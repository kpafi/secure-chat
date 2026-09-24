import UIKit

/// The two page tokens the native chrome must match (client/style.css `bg` and
/// `fg`; android/app/src/main/res/values/colors.xml `app_bg` / `app_fg`), so
/// the bars and the page read as one surface.
enum Theme {
    static let bg = UIColor(red: 0x0D / 255, green: 0x11 / 255, blue: 0x17 / 255, alpha: 1)
    static let fg = UIColor(red: 0xD8 / 255, green: 0xDF / 255, blue: 0xE7 / 255, alpha: 1)
    /// `--accent-fill`: fills under white text (4.6:1; #2f81f7 is 3.8:1).
    static let accentFill = UIColor(red: 0x1F / 255, green: 0x6F / 255, blue: 0xEB / 255, alpha: 1)
    static let accent = UIColor(red: 0x2F / 255, green: 0x81 / 255, blue: 0xF7 / 255, alpha: 1)
    static let muted = UIColor(red: 0x8B / 255, green: 0x94 / 255, blue: 0x9E / 255, alpha: 1)
}
