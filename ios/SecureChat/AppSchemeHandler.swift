import Foundation
import WebKit

/// Serves the bundled client (`<App>.app/web`) under `secure-chat://app/…`.
/// The iOS counterpart of Android's WebViewAssetLoader + the CSP stamp in
/// `shouldInterceptRequest`.
///
/// Strict by construction: GET only, our host only, a path made of plain
/// segments (no `.`/`..`, no hidden files, no percent-encoding at all — the
/// client's file names need none), resolved and re-checked to stay inside the
/// web root after symlinks. Anything else is a 404 with an empty body.
@MainActor
final class AppSchemeHandler: NSObject, WKURLSchemeHandler {
    private let root: URL
    private let csp: () -> String

    init(root: URL, csp: @escaping () -> String) {
        self.root = root.standardizedFileURL.resolvingSymlinksInPath()
        self.csp = csp
    }

    private static let segmentAllowed = CharacterSet(charactersIn:
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@")

    /// Map a request URL to a file inside the web root, or nil.
    func resolve(_ url: URL) -> URL? {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              c.scheme?.lowercased() == AppOrigin.scheme,
              c.percentEncodedHost == AppOrigin.host,
              c.port == nil, c.percentEncodedUser == nil, c.percentEncodedPassword == nil
        else { return nil }
        let path = c.percentEncodedPath
        guard path.hasPrefix("/"), path.count > 1, path.count <= 512 else { return nil }
        let segments = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        var file = root
        for seg in segments {
            guard !seg.isEmpty, !seg.hasPrefix("."),
                  seg.unicodeScalars.allSatisfy({ Self.segmentAllowed.contains($0) })
            else { return nil }
            file.appendPathComponent(String(seg), isDirectory: false)
        }
        let resolved = file.standardizedFileURL.resolvingSymlinksInPath()
        guard resolved.path.hasPrefix(root.path + "/") else { return nil }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: resolved.path, isDirectory: &isDir), !isDir.boolValue
        else { return nil }
        return resolved
    }

    static func mimeType(for file: URL) -> String {
        switch file.pathExtension.lowercased() {
        case "html": return "text/html; charset=utf-8"
        case "js", "mjs": return "text/javascript; charset=utf-8"
        case "css": return "text/css; charset=utf-8"
        case "json": return "application/json"
        case "svg": return "image/svg+xml"
        case "png": return "image/png"
        case "md", "txt": return "text/plain; charset=utf-8"
        default: return "application/octet-stream"
        }
    }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        let request = task.request
        guard let url = request.url else {
            task.didFailWithError(URLError(.badURL))
            return
        }
        let method = request.httpMethod?.uppercased() ?? "GET"
        guard method == "GET", let file = resolve(url), let data = try? Data(contentsOf: file) else {
            respond(task, url: url, status: 404, headers: [:], body: Data())
            return
        }
        let mime = Self.mimeType(for: file)
        var headers = [
            "Content-Type": mime,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        ]
        // Stamp the CSP on every document (there is one: index.html).
        if mime.hasPrefix("text/html") { headers["Content-Security-Policy"] = csp() }
        respond(task, url: url, status: 200, headers: headers, body: data)
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {
        // Responses are produced synchronously in start(); nothing to cancel.
    }

    private func respond(_ task: WKURLSchemeTask, url: URL, status: Int, headers: [String: String], body: Data) {
        var h = headers
        h["Content-Length"] = String(body.count)
        guard let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: h) else {
            task.didFailWithError(URLError(.cannotParseResponse))
            return
        }
        task.didReceive(response)
        task.didReceive(body)
        task.didFinish()
    }
}
