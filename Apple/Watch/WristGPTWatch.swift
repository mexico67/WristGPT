import SwiftUI
import WatchKit

private let mint = Color(red: 0.65, green: 0.96, blue: 0.78)

@main
struct WristGPTWatchApp: App {
    @StateObject private var connection = ConnectionStore()
    var body: some Scene { WindowGroup { WatchHome().environmentObject(connection).preferredColorScheme(.dark) } }
}

@MainActor
final class ChatStore: ObservableObject {
    @Published var messages: [ChatMessage] = []
    @Published var busy = false
    @Published var error: String?
    private var request: Task<Void, Never>?
    private let file = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("history.json")
    init() {
        if let data = try? Data(contentsOf: file), let saved = try? JSONDecoder().decode([ChatMessage].self, from: data) { messages = saved }
    }
    private func save() {
        do { try JSONEncoder().encode(messages).write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]) }
        catch { self.error = "Не удалось сохранить историю на часах." }
    }
    func clear() { request?.cancel(); request = nil; busy = false; messages = []; error = nil; save() }
    func send(_ text: String, connection: ConnectionStore, model: String) {
        guard !busy, let pairing = connection.pairing else { error = "Сначала подключите часы через приложение на iPhone."; return }
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        guard messages.count < 23 else { error = "Начните новый диалог: история заполнена."; return }
        if messages.last?.role == "user" { error = "Повторите предыдущий вопрос или начните новый диалог."; return }
        messages.append(ChatMessage(role: "user", content: text)); save()
        perform(pairing, model: model)
    }
    func retry(connection: ConnectionStore, model: String) {
        guard !busy, messages.last?.role == "user", let pairing = connection.pairing else { return }
        perform(pairing, model: model)
    }
    private func perform(_ pairing: Pairing, model: String) {
        busy = true; error = nil
        let history = messages
        request = Task {
            defer { busy = false }
            do {
                let client = BridgeClient(pairing)
                let text = try await client.ask(history, model: model)
                try Task.checkCancellation()
                messages.append(ChatMessage(role: "assistant", content: text)); save()
                WKInterfaceDevice.current().play(.success)
            } catch is CancellationError { }
            catch { self.error = error.localizedDescription; WKInterfaceDevice.current().play(.failure) }
        }
    }
}

struct WatchHome: View {
    @EnvironmentObject var connection: ConnectionStore
    @StateObject private var chat = ChatStore()
    @AppStorage("selectedModel") private var selectedModel = ""
    @State private var composing = false
    @State private var draft = ""
    @State private var clearConfirmation = false
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if chat.messages.isEmpty {
                        HStack(spacing: 5) {
                            Circle().fill(connection.pairing == nil ? .orange : mint).frame(width: 5, height: 5)
                            Text(connection.pairing == nil ? "НУЖЕН IPHONE" : "ВАША ПОДПИСКА")
                                .font(.system(size: 9, weight: .semibold)).tracking(1.2).foregroundStyle(.secondary)
                        }.padding(.top, 4)
                        Text("Что хотите\nузнать?").font(.system(size: 27, weight: .semibold, design: .rounded)).lineSpacing(-2)
                            .accessibilityAddTraits(.isHeader)
                        Button { draft = ""; composing = true } label: {
                            HStack(spacing: 10) {
                                Image(systemName: "waveform").font(.system(size: 22))
                                Text("Задать вопрос").font(.system(size: 15, weight: .semibold))
                            }.frame(maxWidth: .infinity, minHeight: 49)
                        }.buttonStyle(.plain).foregroundStyle(.black).background(mint, in: RoundedRectangle(cornerRadius: 19))
                        Text("Голосом или текстом").font(.system(size: 11)).foregroundStyle(.secondary).frame(maxWidth: .infinity)
                        ForEach(["Объясни простыми словами", "Переведи фразу"], id: \.self) { prompt in
                            Button { draft = prompt + ": "; composing = true } label: {
                                HStack { Text(prompt).font(.system(size: 12)); Spacer(minLength: 4); Image(systemName: "arrow.up.right").font(.system(size: 10)) }
                                    .padding(11).frame(maxWidth: .infinity, alignment: .leading)
                            }.buttonStyle(.plain).background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
                        }
                    } else {
                        ForEach(chat.messages) { message in
                            VStack(alignment: .leading, spacing: 7) {
                                Text(message.role == "user" ? "ВЫ" : "WRISTGPT").font(.system(size: 9, weight: .bold)).tracking(1)
                                    .foregroundStyle(message.role == "user" ? Color.secondary : mint)
                                Text(message.content).font(.system(size: 15)).lineSpacing(3)
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 7)
                        }
                        if chat.busy { HStack { ProgressView().controlSize(.small); Text("Думаю…").font(.footnote).foregroundStyle(.secondary) } }
                        if chat.messages.last?.role != "user" && !chat.busy {
                            Button("Уточнить") { draft = ""; composing = true }.tint(mint)
                        }
                    }
                    if let error = chat.error {
                        Text(error).font(.footnote).foregroundStyle(.orange)
                        if chat.messages.last?.role == "user" {
                            Button("Повторить") { chat.retry(connection: connection, model: selectedModel) }.disabled(chat.busy)
                        }
                    }
                }.padding(.horizontal, 2).padding(.bottom, 12)
            }
            .navigationTitle("WristGPT").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { settings } label: { Image(systemName: "ellipsis").foregroundStyle(.secondary) }.accessibilityLabel("Настройки")
                }
            }
            .sheet(isPresented: $composing) {
                VStack(spacing: 12) {
                    Text("Ваш вопрос").font(.headline)
                    TextField("Введите или продиктуйте", text: $draft).accessibilityLabel("Ваш вопрос, доступна системная диктовка")
                    Button("Отправить") {
                        composing = false; chat.send(draft, connection: connection, model: selectedModel)
                    }.buttonStyle(.borderedProminent).tint(mint).foregroundStyle(.black)
                        .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || chat.busy)
                }.padding()
            }
        }.tint(mint)
    }
    private var settings: some View {
        List {
            Section("Подключение") {
                Text(connection.status).font(.footnote)
                if let error = connection.error { Text(error).font(.footnote).foregroundStyle(.orange) }
                Button(connection.checking ? "Проверяем…" : "Проверить") {
                    Task {
                        await connection.check()
                        if !connection.availableModels.contains(where: { $0.id == selectedModel }) { selectedModel = connection.availableModels.first?.id ?? "" }
                    }
                }.disabled(connection.checking)
                if !connection.availableModels.isEmpty {
                    Picker("Модель", selection: $selectedModel) {
                        ForEach(connection.availableModels) { Text($0.name).tag($0.id) }
                    }
                }
            }
            Section("Диалог") {
                Button("Новый диалог", role: .destructive) { clearConfirmation = true }
                    .disabled(chat.busy)
                    .confirmationDialog("Удалить историю с часов?", isPresented: $clearConfirmation) {
                        Button("Удалить", role: .destructive) { chat.clear() }
                    }
            }
            Text("WristGPT · личный клиент\nПодписка подключается на Windows. Компьютер должен быть включён и доступен в домашней сети.").font(.footnote).foregroundStyle(.secondary)
        }.navigationTitle("Настройки")
    }
}
