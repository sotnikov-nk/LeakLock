import AppKit
import SwiftUI
import LeakLockCore

@main
struct LeakLockApp: App {
    @StateObject private var model = AppModel()
    @StateObject private var updater = Updater()

    var body: some Scene {
        MenuBarExtra {
            MenuView().environmentObject(model).environmentObject(updater)
        } label: {
            MenuBarIcon(symbol: model.iconName)
        }
        .menuBarExtraStyle(.window)

        Window("Настройки LeakLock", id: "settings") {
            SettingsView().environmentObject(model).environmentObject(updater)
        }
        .windowResizability(.contentSize)
    }
}

/// Status-bar glyph. SwiftUI renders `Image(systemName:)` in the menu bar at the small
/// text size, which looks undersized next to other icons, so the symbol is rasterized
/// at an explicit point size as a template image.
struct MenuBarIcon: View {
    let symbol: String

    var body: some View {
        Image(nsImage: Self.image(symbol))
    }

    static func image(_ symbol: String) -> NSImage {
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "LeakLock")?
            .withSymbolConfiguration(config) ?? NSImage()
        image.isTemplate = true
        return image
    }
}

// MARK: - Menu panel

struct MenuView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var updater: Updater
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        GlassGroup {
            VStack(alignment: .leading, spacing: 12) {
                StatusCard()

                updateBanner

                if !model.helperInstalled {
                    installPrompt(
                        text: "Чтобы блокировать интернет без VPN, нужна служба с правами администратора. Пароль спросят один раз.",
                        button: "Установить службу…"
                    )
                } else if let status = model.status, model.daemonReachable {
                    controls(status)
                } else {
                    installPrompt(
                        text: "Служба установлена, но не отвечает. Попробуйте переустановить её.",
                        button: "Переустановить службу…"
                    )
                }

                if let error = model.lastError {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }

                footer
            }
            .padding(16)
        }
        .frame(width: 330)
    }

    @ViewBuilder
    private func controls(_ status: GuardStatus) -> some View {
        VStack(spacing: 0) {
            Toggle(isOn: binding(\.enabled)) {
                Label("Защита", systemImage: "lock.shield")
                    .font(.body.weight(.semibold))
            }
            .toggleStyle(.switch)
            .disabled(!status.config.enabled && status.config.validServerIPs.isEmpty)
            .padding(.vertical, 10)

            if status.config.validServerIPs.isEmpty {
                Text("Сначала укажите IP VPN-сервера в настройках.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.bottom, 8)
            }

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                Text("Без VPN блокировать")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Picker("Без VPN блокировать", selection: Binding(
                    get: { status.config.blockScope },
                    set: { value in model.updateConfig { $0.blockScope = value } }
                )) {
                    Text("Адреса из VPN").tag(BlockScope.vpnRoutes)
                    Text("Весь интернет").tag(BlockScope.everything)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
            .padding(.vertical, 10)

            Divider()

            Toggle("Локальная сеть без VPN", isOn: binding(\.allowLAN))
                .toggleStyle(.switch)
                .controlSize(.small)
                .padding(.top, 10)
                .padding(.bottom, 6)
            Toggle("DNS без VPN", isOn: binding(\.allowDNS))
                .toggleStyle(.switch)
                .controlSize(.small)
                .padding(.bottom, 6)
            Toggle("Доверять маршрутизации клиента", isOn: binding(\.trustClientRouting))
                .toggleStyle(.switch)
                .controlSize(.small)
                .help("Пока VPN проверен, не блокировать трафик мимо туннеля: прямые соединения, которые отправляет сам VPN-клиент (списки Direct в Incy). Включайте только вместе с kill switch клиента.")
                .padding(.bottom, 10)
        }
        .padding(.horizontal, 14)
        .glassCard()

        HStack(spacing: 8) {
            Button {
                model.recheck()
            } label: {
                Label("Проверить IP", systemImage: "arrow.clockwise")
                    .frame(maxWidth: .infinity)
            }
            .disabled(!status.config.enabled)

            if model.helperNeedsUpdate {
                Button {
                    model.installHelper()
                } label: {
                    Label("Обновить службу", systemImage: "arrow.down.circle")
                        .frame(maxWidth: .infinity)
                }
                .disabled(model.busy)
            }
        }
        .glassButtons()
    }

    @ViewBuilder
    private var updateBanner: some View {
        switch updater.phase {
        case .available(let release):
            HStack(spacing: 10) {
                Label("Доступна версия \(release.version)", systemImage: "arrow.down.app")
                    .font(.callout)
                Spacer(minLength: 0)
                Button("Обновить") { updater.install(release) }
                    .glassButtons(prominent: true)
            }
            .padding(12)
            .glassCard()
        case .installing(let release):
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text("Устанавливаю \(release.version), приложение перезапустится…")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(12)
            .glassCard()
        default:
            EmptyView()
        }
    }

    private var updateNote: String? {
        switch updater.phase {
        case .checking: return "Проверяю обновления…"
        case .upToDate: return "Установлена последняя версия \(LeakLockVersion.current)."
        case .failed(let message): return message
        default: return nil
        }
    }

    private func installPrompt(text: String, button: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                model.installHelper()
            } label: {
                Text(button).frame(maxWidth: .infinity)
            }
            .glassButtons(prominent: true)
            .disabled(model.busy)
        }
        .padding(14)
        .glassCard()
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button {
                    openWindow(id: "settings")
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Label("Настройки", systemImage: "gearshape")
                }
                Spacer()
                Button {
                    updater.check()
                } label: {
                    Label("Обновления", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(updater.busy)
                Spacer()
                Button {
                    NSApp.terminate(nil)
                } label: {
                    Label("Выйти", systemImage: "power")
                }
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)

            if let note = updateNote {
                Text(note)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Защита продолжает работать и после выхода из приложения.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 4)
    }

    private func binding(_ keyPath: WritableKeyPath<GuardConfig, Bool>) -> Binding<Bool> {
        Binding(
            get: { model.status?.config[keyPath: keyPath] ?? false },
            set: { value in model.updateConfig { $0[keyPath: keyPath] = value } }
        )
    }
}

/// Large status header: tinted glass badge with the shield and the current state.
struct StatusCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: model.iconName)
                .font(.system(size: 26, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(model.tint)
                .frame(width: 54, height: 54)
                .glassBadge(tint: model.tint)

            VStack(alignment: .leading, spacing: 3) {
                Text(model.headline)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(model.details, id: \.self) { line in
                    Text(line)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .glassCard()
    }
}

// MARK: - Settings window

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var updater: Updater
    @State private var newIP = ""

    var body: some View {
        Form {
            Section {
                if let config = model.status?.config {
                    if config.vpnServerIPs.isEmpty {
                        Text("Пока не указано ни одного адреса.").foregroundStyle(.secondary)
                    }
                    ForEach(config.vpnServerIPs, id: \.self) { ip in
                        HStack {
                            Image(systemName: "server.rack").foregroundStyle(.secondary)
                            Text(ip).font(.body.monospaced())
                            Spacer()
                            Button(role: .destructive) {
                                model.updateConfig { config in config.vpnServerIPs.removeAll { $0 == ip } }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                            }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.red)
                        }
                    }
                    HStack {
                        TextField("Например, 203.0.113.10", text: $newIP)
                            .textFieldStyle(.roundedBorder)
                            .onSubmit(addIP)
                        Button("Добавить", action: addIP)
                            .glassButtons(prominent: true)
                            .disabled(IPAddress(newIP) == nil)
                    }
                    if let status = model.status, status.state == .ipMismatch, let ip = status.externalIP {
                        Button("Добавить текущий внешний IP \(ip)") {
                            model.updateConfig { $0.vpnServerIPs.append(ip) }
                        }
                        .glassButtons()
                        Text("Нажимайте, только если VPN сейчас точно подключён.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    Text("Служба не отвечает, настройки недоступны.").foregroundStyle(.secondary)
                }
            } header: {
                Text("IP-адреса VPN-сервера")
            } footer: {
                Text("Трафик к этим адресам разрешён всегда, чтобы VPN мог подключиться. Интернет открывается, только когда внешний IP совпадает с одним из них.")
                    .foregroundStyle(.secondary)
            }

            if let config = model.status?.config {
                Section("Проверка внешнего IP") {
                    Stepper(
                        "Перепроверять каждые \(config.recheckIntervalSeconds) с",
                        value: Binding(
                            get: { config.recheckIntervalSeconds },
                            set: { value in model.updateConfig { $0.recheckIntervalSeconds = value } }
                        ),
                        in: 15...3600,
                        step: 15
                    )
                }
                Section {
                    Stepper(
                        "Проверять каждые \(config.pfCheckIntervalSeconds) с",
                        value: Binding(
                            get: { config.pfCheckIntervalSeconds },
                            set: { value in model.updateConfig { $0.pfCheckIntervalSeconds = value } }
                        ),
                        in: 1...10
                    )
                } header: {
                    Text("Проверка правил pf")
                } footer: {
                    Text("Как часто служба проверяет, что pf включён и правила LeakLock не изменила другая программа. Обрыв VPN блокируется мгновенно при любом значении. Больший интервал чуть экономит батарею, но вмешательство в pf будет замечено позже.")
                        .foregroundStyle(.secondary)
                }
            }

            if let status = model.status, status.config.blockScope == .vpnRoutes {
                Section {
                    LabeledContent("Маршрутов VPN под защитой", value: status.protectedCount.map { "\($0)" } ?? "пока нет")
                    Button("Забыть выученные маршруты") { model.resetLearnedRoutes() }
                        .glassButtons()
                } header: {
                    Text("Адреса из VPN")
                } footer: {
                    Text("LeakLock запоминает всё, что VPN когда-либо направлял в туннель, и сам этот список не сокращает. Если вы убрали сайты из списка VPN, а они всё равно блокируются, нажмите кнопку при подключённом VPN: список соберётся заново по текущим маршрутам.")
                        .foregroundStyle(.secondary)
                }
            }

            Section("Служба и запуск") {
                Toggle("Запускать LeakLock при входе", isOn: Binding(
                    get: { model.launchAtLogin },
                    set: { model.launchAtLogin = $0 }
                ))
                LabeledContent("Служба", value: model.helperInstalled
                    ? "установлена, версия \(model.status?.daemonVersion ?? "?")"
                    : "не установлена")
                HStack {
                    Button(model.helperInstalled ? "Переустановить…" : "Установить…") { model.installHelper() }
                    if model.helperInstalled {
                        Button("Удалить службу…", role: .destructive) { model.uninstallHelper() }
                    }
                }
                .glassButtons()
                .disabled(model.busy)
                Text("После удаления службы блокировка снимается полностью.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Обновления") {
                LabeledContent("Версия приложения", value: LeakLockVersion.current)
                HStack {
                    Button("Проверить обновления") { updater.check() }
                        .disabled(updater.busy)
                    if let release = updater.available {
                        Button("Установить \(release.version)") { updater.install(release) }
                        Link("Что нового", destination: release.pageURL)
                    }
                }
                .glassButtons()
                Group {
                    switch updater.phase {
                    case .idle: EmptyView()
                    case .checking: Text("Проверяю…")
                    case .upToDate: Text("Установлена последняя версия.")
                    case .available(let release): Text("Доступна версия \(release.version). После установки приложение перезапустится и попросит пароль, чтобы обновить службу.")
                    case .installing(let release): Text("Скачиваю и устанавливаю \(release.version)…")
                    case .failed(let message): Text(message).foregroundStyle(.red)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            if let error = model.lastError {
                Text(error).foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .translucentWindow()
        .frame(width: 480)
        .frame(minHeight: 520)
    }

    private func addIP() {
        guard let ip = IPAddress(newIP) else { return }
        model.updateConfig { config in
            if !config.vpnServerIPs.contains(ip.description) { config.vpnServerIPs.append(ip.description) }
        }
        newIP = ""
    }
}
