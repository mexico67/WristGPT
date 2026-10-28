import SwiftUI

@main
struct WristGPTPhoneApp: App {
    @StateObject private var connection = ConnectionStore()
    var body: some Scene { WindowGroup { PhoneView().environmentObject(connection).preferredColorScheme(.dark) } }
}

struct PhoneView: View {
    @EnvironmentObject var connection: ConnectionStore
    @State private var code = ""
    @State private var feedback = ""
    private let mint = Color(red: 0.65, green: 0.96, blue: 0.78)
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    Image(systemName: "waveform").font(.system(size: 44, weight: .medium)).foregroundStyle(mint).padding(.top, 24)
                    Text("Умный ответ.\nПрямо на запястье.").font(.system(size: 36, weight: .semibold, design: .rounded))
                    Text("Подключите подписку ChatGPT на компьютере, затем передайте подключение часам.")
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 14) {
                        Label("Подключение", systemImage: "link").font(.headline)
                        Text("Откройте WristGPT на Windows → «Подключить часы». Вставьте код ниже.").foregroundStyle(.secondary)
                        TextEditor(text: $code).font(.system(.caption, design: .monospaced)).frame(height: 130)
                            .padding(8).background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14))
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                            .accessibilityLabel("Код подключения с компьютера")
                        Button {
                            do {
                                let pairing = try JSONDecoder().decode(Pairing.self, from: Data(code.utf8))
                                try connection.save(pairing)
                                code = ""; feedback = "Код сохранён. Часы получат его через Watch Connectivity."
                                Task { await connection.check() }
                            } catch { feedback = error.localizedDescription }
                        } label: { Text("Подключить Apple Watch").frame(maxWidth: .infinity).padding(.vertical, 8) }
                        .buttonStyle(.borderedProminent).tint(mint).foregroundStyle(.black).disabled(code.isEmpty)
                        if !feedback.isEmpty { Text(feedback).font(.footnote).foregroundStyle(.secondary) }
                    }
                    if connection.pairing != nil {
                        VStack(alignment: .leading, spacing: 14) {
                            Label(connection.status, systemImage: "desktopcomputer").font(.headline)
                            if let error = connection.error { Text(error).foregroundStyle(.orange).font(.footnote) }
                            Button(connection.checking ? "Проверяем…" : "Проверить подключение") { Task { await connection.check() } }
                                .disabled(connection.checking)
                            Button("Повторно отправить код на часы") {
                                do { if let pairing = connection.pairing { try connection.save(pairing); feedback = "Код отправлен." } }
                                catch { feedback = error.localizedDescription }
                            }
                        }
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Всегда под рукой").font(.headline)
                        Text("Компьютер должен быть включён. Компьютер, iPhone и часы должны иметь доступ к одной домашней сети. Ввод голосом выполняет системная диктовка watchOS.")
                            .font(.footnote).foregroundStyle(.secondary)
                        Link("Управлять использованием подписки ↗", destination: URL(string: "https://chatgpt.com/settings/usage")!)
                    }
                }.padding(24)
            }.background(Color.black).navigationTitle("WristGPT").navigationBarTitleDisplayMode(.inline)
        }.tint(mint)
    }
}
