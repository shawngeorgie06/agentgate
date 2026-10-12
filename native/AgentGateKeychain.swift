import Cocoa
import Security
import Foundation

let service = "com.agentgate.master-password"
func query(_ account: String) -> [String: Any] {
    return [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: false]
}
func readSecret(_ account: String) -> Data? {
    var q = query(account)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess else { return nil }
    return result as? Data
}
func saveSecret(_ account: String, _ value: Data) -> Bool {
    let q = query(account)
    let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: value] as CFDictionary)
    if status == errSecSuccess { return true }
    guard status == errSecItemNotFound else { return false }
    var add = q
    add[kSecValueData as String] = value
    add[kSecAttrLabel as String] = "AgentGate master password"
    return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
}
let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.first == "--help" {
    print("AgentGate app; private helper commands: read --account PATH, forget --account PATH")
    exit(0)
}
if arguments.first == "read" || arguments.first == "forget" {
    guard arguments.count == 3, arguments[1] == "--account" else { exit(2) }
    if arguments[0] == "forget" {
        let status = SecItemDelete(query(arguments[2]) as CFDictionary)
        exit(status == errSecSuccess || status == errSecItemNotFound ? 0 : 1)
    }
    guard let value = readSecret(arguments[2]), value.count > 0, value.count <= 4096 else { exit(1) }
    FileHandle.standardOutput.write(value)
    exit(0)
}
struct Settings: Decodable {
    let python: String
    let project_dir: String
    let config_dir: String
    let port: Int
    let label: String
}
final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
final class ReadinessResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set(_ ready: Bool) { lock.lock(); value = ready; lock.unlock() }
    func get() -> Bool { lock.lock(); defer { lock.unlock() }; return value }
}
func loadedSettings() -> Settings? {
    guard let resource = Bundle.main.url(forResource: "settings", withExtension: "json"),
          let data = try? Data(contentsOf: resource), let s = try? JSONDecoder().decode(Settings.self, from: data),
          (1...65535).contains(s.port), s.label == "com.agentgate.broker" else { return nil }
    return s
}
if arguments.first == "--check-config" { exit(loadedSettings() == nil ? 1 : 0) }
func alert(_ message: String, _ detail: String) {
    let a = NSAlert(); a.messageText = message; a.informativeText = detail
    a.addButton(withTitle: "OK"); a.runModal()
}
func subprocess(_ executable: String, _ args: [String], cwd: String? = nil, input: Data? = nil) -> Bool {
    let p = Process(); p.executableURL = URL(fileURLWithPath: executable); p.arguments = args
    if let directory = cwd { p.currentDirectoryURL = URL(fileURLWithPath: directory) }
    p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
    let pipe = Pipe(); p.standardInput = pipe
    let done = DispatchSemaphore(value: 0)
    p.terminationHandler = { _ in done.signal() }
    do {
        try p.run()
        if let data = input { try pipe.fileHandleForWriting.write(contentsOf: data) }
        try pipe.fileHandleForWriting.close()
        if done.wait(timeout: .now() + 15) == .timedOut {
            if p.isRunning { p.terminate() }
            if done.wait(timeout: .now() + 1) == .timedOut && p.isRunning {
                _ = kill(p.processIdentifier, SIGKILL)
                _ = done.wait(timeout: .now() + 1)
            }
            return false
        }
        return p.terminationStatus == 0
    } catch { if p.isRunning { p.terminate() }; return false }
}
final class Delegate: NSObject, NSApplicationDelegate {
    var settings: Settings!
    var account = ""
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        guard let s = loadedSettings() else {
            alert("AgentGate could not start", "App configuration is missing or invalid."); NSApp.terminate(nil); return
        }
        settings = s
        account = URL(fileURLWithPath: s.config_dir).appendingPathComponent("credentials.json").resolvingSymlinksInPath().path
        let menu = NSMenu(); let appMenu = NSMenu(); let top = NSMenuItem(); top.submenu = appMenu; menu.addItem(top)
        appMenu.addItem(withTitle: "Open AgentGate", action: #selector(openApp), keyEquivalent: "o")
        appMenu.addItem(withTitle: "Set up saved unlock…", action: #selector(setup), keyEquivalent: "")
        appMenu.addItem(withTitle: "Forget saved unlock…", action: #selector(forget), keyEquivalent: "")
        appMenu.addItem(withTitle: "Enable automatic startup", action: #selector(enableStartup), keyEquivalent: "")
        appMenu.addItem(withTitle: "Disable automatic startup…", action: #selector(disableStartup), keyEquivalent: "")
        appMenu.addItem(NSMenuItem.separator()); appMenu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        for item in appMenu.items where item.action != #selector(NSApplication.terminate(_:)) { item.target = self }
        NSApp.mainMenu = menu
        if arguments.first == "setup" || readSecret(account) == nil { setup() } else { openApp() }
    }
    @objc func setup() {
        let a = NSAlert(); a.messageText = "Save AgentGate unlock in macOS Keychain?"
        a.informativeText = "Enter your existing AgentGate master password. Saving it lets AgentGate run after login without Terminal. It stays in your Mac’s login Keychain."
        a.addButton(withTitle: "Save and Open"); a.addButton(withTitle: "Cancel")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 24)); a.accessoryView = field
        a.window.initialFirstResponder = field
        guard a.runModal() == .alertFirstButtonReturn else { return }
        let value = Data(field.stringValue.utf8); field.stringValue = ""
        guard value.count > 0, value.count <= 4096,
              subprocess(settings.python, ["-m", "broker.mac_keychain", "validate", "--credentials-path", account], cwd: settings.project_dir, input: value) else {
            alert("Could not unlock saved credentials", "Use the original AgentGate master password. Nothing was saved."); return
        }
        guard saveSecret(account, value) else { alert("Could not save unlock", "Check your macOS login Keychain, then try again."); return }
        openApp()
    }
    @objc func forget() {
        let a = NSAlert(); a.messageText = "Forget saved AgentGate unlock?"
        a.informativeText = "This removes the saved master password. An already running broker stays unlocked until stopped; future starts require setup again."
        a.addButton(withTitle: "Forget"); a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        let status = SecItemDelete(query(account) as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound { alert("Could not forget unlock", "Check your login Keychain.") }
    }
    var launchAgentPath: String {
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/com.agentgate.broker.plist").path
    }
    @objc func enableStartup() {
        let fm = FileManager.default
        if !fm.fileExists(atPath: launchAgentPath), fm.fileExists(atPath: launchAgentPath + ".disabled") {
            do { try fm.moveItem(atPath: launchAgentPath + ".disabled", toPath: launchAgentPath) }
            catch { alert("Could not enable startup", "The saved login configuration could not be restored."); return }
        }
        guard fm.fileExists(atPath: launchAgentPath) else { alert("Could not enable startup", "Reinstall AgentGate’s background service configuration."); return }
        guard subprocess("/bin/launchctl", ["enable", "gui/\(getuid())/\(settings.label)"]) else {
            alert("Could not enable startup", "The login configuration was restored, but macOS could not enable its service. Automatic startup is not confirmed.")
            return
        }
        _ = subprocess("/bin/launchctl", ["bootstrap", "gui/\(getuid())", launchAgentPath])
        if !subprocess("/bin/launchctl", ["print", "gui/\(getuid())/\(settings.label)"]) {
            alert("Could not enable startup", "Your login service could not be loaded.")
        }
    }
    @objc func disableStartup() {
        let a = NSAlert(); a.messageText = "Disable automatic startup?"
        a.informativeText = "This stops AgentGate’s background broker. Agents cannot connect until you enable startup again. Your connections and saved unlock stay saved."
        a.addButton(withTitle: "Disable"); a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        let fm = FileManager.default
        do {
            if fm.fileExists(atPath: launchAgentPath) {
                if fm.fileExists(atPath: launchAgentPath + ".disabled") { throw NSError(domain: "AgentGate", code: 1) }
                try fm.moveItem(atPath: launchAgentPath, toPath: launchAgentPath + ".disabled")
            }
        } catch { alert("Could not disable startup", "The login configuration could not be moved safely."); return }
        let disabled = subprocess("/bin/launchctl", ["disable", "gui/\(getuid())/\(settings.label)"])
        _ = subprocess("/bin/launchctl", ["bootout", "gui/\(getuid())/\(settings.label)"])
        let deadline = Date().addingTimeInterval(5)
        var loaded = subprocess("/bin/launchctl", ["print", "gui/\(getuid())/\(settings.label)"])
        while loaded && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.2)
            loaded = subprocess("/bin/launchctl", ["print", "gui/\(getuid())/\(settings.label)"])
        }
        if loaded {
            alert("AgentGate may still be running", "The login configuration was moved aside, but its service is still registered. Background shutdown was not confirmed.")
        } else if !disabled {
            alert("Automatic startup was not fully disabled", "The service was unloaded and the login configuration moved aside, but macOS could not mark the service disabled.")
        }
    }
    @objc func openApp() {
        let tokenPath = URL(fileURLWithPath: settings.config_dir).appendingPathComponent("operator-token").path
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: tokenPath),
              attrs[.type] as? FileAttributeType == .typeRegular,
              (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              (attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600,
              let token = try? String(contentsOfFile: tokenPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              token.range(of: "^[A-Za-z0-9_-]{32,512}$", options: .regularExpression) != nil else {
            alert("Could not open AgentGate", "The private app credential is missing or unsafe."); return
        }
        let s = settings!
        DispatchQueue.global().async {
            func reachable() -> Bool {
                let sem = DispatchSemaphore(value: 0)
                let result = ReadinessResult()
                var req = URLRequest(url: URL(string: "http://127.0.0.1:\(s.port)/api/status")!)
                req.timeoutInterval = 2; req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                let config = URLSessionConfiguration.ephemeral
                config.urlCache = nil
                let session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
                let task = session.dataTask(with: req) { data, response, _ in
                    let object = data.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
                    result.set((response as? HTTPURLResponse)?.statusCode == 200 && object?["ok"] as? Bool == true)
                    sem.signal()
                }
                task.resume()
                if sem.wait(timeout: .now() + 3) == .timedOut { task.cancel(); session.invalidateAndCancel(); return false }
                session.finishTasksAndInvalidate(); return result.get()
            }
            var ready = reachable()
            if !ready {
                if !subprocess("/bin/launchctl", ["print", "gui/\(getuid())/\(s.label)"]) {
                    if FileManager.default.fileExists(atPath: self.launchAgentPath) {
                        _ = subprocess("/bin/launchctl", ["bootstrap", "gui/\(getuid())", self.launchAgentPath])
                    }
                }
                _ = subprocess("/bin/launchctl", ["kickstart", "gui/\(getuid())/\(s.label)"])
                let until = Date().addingTimeInterval(20)
                while Date() < until && !ready { Thread.sleep(forTimeInterval: 0.5); ready = reachable() }
            }
            DispatchQueue.main.async {
                if ready {
                    NSWorkspace.shared.open(URL(string: "http://127.0.0.1:\(s.port)/app#key=\(token)")!)
                } else { alert("AgentGate is not ready", "Your saved unlock may need setup, or another process may be using its port. Choose Set up saved unlock from the AgentGate menu.") }
            }
        }
    }
}
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = Delegate(); app.delegate = delegate
app.run()
