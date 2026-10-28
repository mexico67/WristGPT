import Foundation
import Combine
import Security
import CryptoKit
import WatchConnectivity

struct Pairing: Codable {
    let url: String
    let token: String
    let fingerprint: String

    func validated() throws -> Pairing {
        guard let parsed = URLComponents(string: url), parsed.scheme == "https",
              parsed.host != nil, parsed.user == nil, parsed.password == nil,
              parsed.query == nil, parsed.fragment == nil,
              parsed.path.isEmpty || parsed.path == "/",
              token.count >= 32, fingerprint.count == 64,
              fingerprint.allSatisfy({ $0.isHexDigit }) else {
            throw ClientError.message("Некорректный код подключения.")
        }
        return self
    }
}

enum ClientError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case let .message(text) = self { return text }; return nil }
}

enum SecureStorage {
    static func read() -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "WristGPT.Connection", kSecAttrAccount as String: "bridge",
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var value: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &value) == errSecSuccess else { return nil }
        return value as? Data
    }
    static func save(_ data: Data) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "WristGPT.Connection", kSecAttrAccount as String: "bridge"]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
                throw ClientError.message("Не удалось сохранить подключение в Keychain.")
            }
        } else if status != errSecSuccess { throw ClientError.message("Keychain недоступен.") }
    }
}

final class PinnedTLS: NSObject, URLSessionDelegate, @unchecked Sendable {
    let fingerprint: String
    init(_ fingerprint: String) { self.fingerprint = fingerprint.lowercased() }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let certificate = chain.first else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        let bytes = SecCertificateCopyData(certificate) as Data
        let actual = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        guard actual == fingerprint else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        // Trust exactly the certificate paired from the local PC, including its self-signed chain.
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

struct AvailableModel: Codable, Identifiable, Hashable {
    let id: String
    let name: String
}
struct ChatMessage: Codable, Identifiable {
    var id = UUID()
    let role: String
    let content: String
}
struct SessionInfo: Decodable {
    let connected: Bool
    let sharing: Bool
    let email: String
}

final class BridgeClient {
    private let pairing: Pairing
    private let session: URLSession
    init(_ pairing: Pairing) {
        self.pairing = pairing
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 180
        config.timeoutIntervalForResource = 190
        session = URLSession(configuration: config, delegate: PinnedTLS(pairing.fingerprint), delegateQueue: nil)
    }
    deinit { session.invalidateAndCancel() }
    func request<T: Decodable>(_ path: String, body: Data? = nil) async throws -> T {
        guard let url = URL(string: pairing.url.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path) else {
            throw ClientError.message("Некорректный адрес компьютера.")
        }
        var request = URLRequest(url: url)
        request.setValue("Bearer " + pairing.token, forHTTPHeaderField: "Authorization")
        if let body {
            request.httpMethod = "POST"; request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ClientError.message("Нет ответа от компьютера.") }
        guard http.statusCode == 200 else {
            let error = try? JSONDecoder().decode([String: String].self, from: data)
            throw ClientError.message(error?["error"] ?? "Ошибка подключения. Проверьте код и сеть Wi-Fi.")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func models() async throws -> [AvailableModel] {
        struct Result: Decodable { let models: [AvailableModel] }
        let result: Result = try await request("/api/models")
        return result.models
    }
    func ask(_ messages: [ChatMessage], model: String) async throws -> String {
        struct Message: Encodable { let role: String; let content: String }
        struct Payload: Encodable { let messages: [Message]; let model: String }
        struct Answer: Decodable { let text: String }
        let body = try JSONEncoder().encode(Payload(messages: messages.map { Message(role: $0.role, content: $0.content) }, model: model))
        let result: Answer = try await request("/api/ask", body: body)
        return result.text
    }
}

final class WatchLink: NSObject, WCSessionDelegate {
    var onPairing: ((Pairing) -> Void)?
    var current: Pairing?
    override init() {
        super.init()
        if WCSession.isSupported() { WCSession.default.delegate = self; WCSession.default.activate() }
    }
    func send(_ pairing: Pairing) throws {
        current = pairing
        guard WCSession.default.activationState == .activated else { return }
        let data = try JSONEncoder().encode(pairing)
        try WCSession.default.updateApplicationContext(["pairing": data])
    }
    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        if let data = session.receivedApplicationContext["pairing"] as? Data,
           let pairing = try? JSONDecoder().decode(Pairing.self, from: data).validated() { onPairing?(pairing) }
        #if os(iOS)
        if let current { try? send(current) }
        #endif
    }
    func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        if let data = applicationContext["pairing"] as? Data,
           let pairing = try? JSONDecoder().decode(Pairing.self, from: data).validated() { onPairing?(pairing) }
    }
    #if os(iOS)
    func sessionDidBecomeInactive(_ session: WCSession) {}
    func sessionDidDeactivate(_ session: WCSession) { session.activate() }
    #endif
}

@MainActor
final class ConnectionStore: ObservableObject {
    @Published var pairing: Pairing?
    @Published var status = "Подключите компьютер"
    @Published var error: String?
    @Published var availableModels: [AvailableModel] = []
    @Published var checking = false
    private let link = WatchLink()
    init() {
        if let data = SecureStorage.read(), let saved = try? JSONDecoder().decode(Pairing.self, from: data).validated() {
            pairing = saved; status = "Подключение сохранено"; link.current = saved
        }
        link.onPairing = { [weak self] value in
            Task { @MainActor in
                do { try self?.save(value, transmit: false) }
                catch { self?.error = error.localizedDescription }
            }
        }
    }
    func save(_ value: Pairing, transmit: Bool = true) throws {
        let validated = try value.validated()
        try SecureStorage.save(JSONEncoder().encode(validated))
        pairing = validated; status = "Подключение сохранено"; availableModels = []
        if transmit { try link.send(validated) }
    }
    func check() async {
        guard let pairing, !checking else { return }
        checking = true; error = nil
        defer { checking = false }
        do {
            let client = BridgeClient(pairing)
            let result: SessionInfo = try await client.request("/api/session")
            guard result.connected && result.sharing else { throw ClientError.message("Войдите в ChatGPT на компьютере и разрешите использование подписки.") }
            availableModels = try await client.models()
            guard !availableModels.isEmpty else { throw ClientError.message("Для аккаунта не найдены доступные модели.") }
            status = result.email
        } catch { self.error = error.localizedDescription; status = "Нет соединения" }
    }
}
