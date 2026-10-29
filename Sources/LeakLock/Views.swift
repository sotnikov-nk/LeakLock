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

        Window("Настройки Breaker", id: "settings") {
            SettingsView().environmentObject(model).environmentObject(updater)
        }
        .windowResizability(.contentSize)
    }
}

/// Status-bar glyph. SwiftUI renders `Image(systemName:)` in the menu bar at the small
/// text size, which looks undersized next to other icons, so the symbol is drawn at an
/// explicit point size as a template image.
///
/// The image keeps the symbol's own size in points but is drawn on demand, so each
/// display renders it at its own scale. A plain symbol image could be laid out by its
/// pixel size when the menu bar moved to a display with a different scale (a TV at 1x),
/// and grew there.
struct MenuBarIcon: View {
    let symbol: String

    var body: some View {
        Image(nsImage: Self.image(symbol))
    }

    static func image(_ symbol: String) -> NSImage {
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
        guard let glyph = NSImage(systemSymbolName: symbol, accessibilityDescription: "Breaker")?
            .withSymbolConfiguration(config) else { return NSImage() }
        let image = NSImage(size: glyph.size, flipped: false) { rect in
            glyph.draw(in: rect)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Breaker"
        return image
    }
}

// MARK: - Menu panel

struct MenuView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var updater: Updater
    @Environment(\.openWindow) private var openWindow
    @State private var ipWarningPulse = false

    var body: some View {
        GlassGroup {
            VStack(alignment: .leading, spacing: 12) {
                StatusCard()

                updateBanner

                if !model.helperInstalled {
                    installPrompt(
                        text: "Чтобы блокировать интернет без VPN, нужна служба с правами администратора. Пароль понадобится один раз.",
                        button: "Установить службу…"
                    )
                } else if let status = model.status, model.daemonReachable {
                    controls(status)
                } else {
                    installPrompt(
                        text: "Служба не отвечает. Переустановите её.",
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
        if status.config.validServerIPs.isEmpty {
            serverIPWarning
        }

        VStack(spacing: 0) {
            settingRow(Help.protection, isOn: protectionBinding(status)) {
                Label("Защита", systemImage: "lock.shield")
                    .font(.body.weight(.semibold))
            }
            .controlSize(.regular)
            .padding(.vertical, 10)

            Divider()

            sectionHeader("Для всех VPN")
            settingRow(Help.lan, isOn: binding(\.allowLAN)) { Text("Локальная сеть без VPN") }
                .padding(.bottom, 6)
            settingRow(Help.dns, isOn: binding(\.allowDNS)) { Text("DNS без VPN") }
                .padding(.bottom, 10)

            Divider()

            sectionHeader("AmneziaVPN")
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 4) {
                    Text("Без VPN блокировать")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HelpButton(text: Help.amneziaScope)
                }
                Picker("Без VPN блокировать", selection: Binding(
                    get: { status.config.blockScope },
                    set: { value in model.updateConfig { $0.blockScope = value } }
                )) {
                    Text("Адреса из VPN").tag(BlockScope.vpnRoutes)
                    Text("Весь интернет").tag(BlockScope.everything)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                note(status.config.blockScope == .vpnRoutes
                    ? "Закрыто только то, что Amnezia ведёт через туннель. Сайты из исключений открываются напрямую."
                    : "Закрыт весь интернет, кроме сервера VPN.")
            }
            .padding(.bottom, 10)

            Divider()

            sectionHeader("Incy и Happ")
            note("Сайты из прямых правил клиента открываются напрямую, пока VPN подключён. Включите kill switch в клиенте (в Happ: «Включить все сети»).")
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

    /// Without a server address protection cannot turn on, so say so up front
    /// instead of leaving a greyed-out switch.
    private var serverIPWarning: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Укажите IP VPN-сервера", systemImage: "exclamationmark.triangle.fill")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.orange)
            Text("Без него защита не включится: Breaker сверяет с ним внешний IP.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                openSettings()
            } label: {
                Text("Указать IP…").frame(maxWidth: .infinity)
            }
            .glassButtons(prominent: true)
        }
        .padding(14)
        .glassCard()
        .scaleEffect(ipWarningPulse ? 1.04 : 1)
        .animation(.spring(response: 0.25, dampingFraction: 0.4), value: ipWarningPulse)
    }

    /// Switching protection on without a server address points at the warning and
    /// opens the settings, rather than doing nothing.
    private func protectionBinding(_ status: GuardStatus) -> Binding<Bool> {
        Binding(
            get: { status.config.enabled },
            set: { value in
                if value && status.config.validServerIPs.isEmpty {
                    ipWarningPulse = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { ipWarningPulse = false }
                    openSettings()
                    return
                }
                model.updateConfig { $0.enabled = value }
            }
        )
    }

    private func openSettings() {
        openWindow(id: "settings")
        NSApp.activate(ignoringOtherApps: true)
    }

    private func settingRow<Title: View>(
        _ help: String, isOn: Binding<Bool>, @ViewBuilder title: () -> Title
    ) -> some View {
        HStack(spacing: 4) {
            title()
            HelpButton(text: help)
            Spacer(minLength: 8)
            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
        }
        .controlSize(.small)
    }

    private func note(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
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
                Text("Устанавливаю \(release.version). Приложение перезапустится…")
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
                    openSettings()
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
            Text("Защита работает и после выхода из приложения.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 4)
    }

    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 10)
            .padding(.bottom, 6)
    }

    private func binding(_ keyPath: WritableKeyPath<GuardConfig, Bool>) -> Binding<Bool> {
        Binding(
            get: { model.status?.config[keyPath: keyPath] ?? false },
            set: { value in model.updateConfig { $0[keyPath: keyPath] = value } }
        )
    }
}

/// "?" next to a setting; opens the full explanation in a popover.
struct HelpButton: View {
    let text: String
    @State private var shown = false

    var body: some View {
        Button {
            shown.toggle()
        } label: {
            Image(systemName: "questionmark.circle")
                .foregroundStyle(.secondary)
        }
        .buttonStyle(.borderless)
        .controlSize(.small)
        .accessibilityLabel("Подробнее")
        .popover(isPresented: $shown, arrowEdge: .bottom) {
            Text(text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
                .frame(width: 280, alignment: .leading)
                .padding(14)
        }
    }
}

/// Full explanations behind the "?" buttons.
enum Help {
    static let protection = """
        Breaker пропускает трафик, только когда VPN подключён и внешний IP совпадает \
        с адресом сервера. В остальное время трафик блокирует файрвол macOS.

        Защита работает и после выхода из приложения.
        """
    static let lan = """
        Принтер, сетевые диски и роутер будут доступны и без VPN. Интернет при этом \
        остаётся закрытым.

        AirDrop, AirPlay и повтор экрана iPhone работают при любом значении.
        """
    static let dns = """
        Нужен, только если в VPN-клиенте сервер указан доменом, а не IP: иначе клиент \
        не узнает адрес сервера.

        Без VPN DNS-запросы пойдут мимо туннеля, и провайдер увидит, какие сайты вы открываете.
        """
    static let amneziaScope = """
        «Весь интернет»: без VPN закрыто всё, кроме сервера VPN. Подходит для чужих сетей.

        «Адреса из VPN»: закрыто только то, что Amnezia ведёт через туннель. Сайты \
        из исключений раздельного туннелирования открываются напрямую. Breaker запоминает \
        адреса туннеля и держит их закрытыми, пока VPN выключен.
        """
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
                        Text("Адресов пока нет. Без них защита не включится.").foregroundStyle(.orange)
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
                        Text("Нажимайте, только если VPN точно подключён.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    Text("Служба не отвечает, настройки недоступны.").foregroundStyle(.secondary)
                }
            } header: {
                Text("IP-адреса VPN-сервера")
            } footer: {
                Text("К этим адресам трафик разрешён всегда, чтобы VPN мог подключиться. Интернет откроется, когда внешний IP совпадёт с одним из них.")
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
                    Text("Как часто служба проверяет, что pf включён и правила Breaker никто не менял. Обрыв VPN блокируется сразу при любом значении. Редкая проверка чуть бережёт батарею, но чужое вмешательство в pf будет заметно позже.")
                        .foregroundStyle(.secondary)
                }
            }

            if let status = model.status, status.config.blockScope == .vpnRoutes {
                Section {
                    LabeledContent("Клиент", value: (status.routesClient ?? .amnezia).title)
                    LabeledContent("Маршрутов под защитой", value: status.protectedCount.map { "\($0)" } ?? "пока нет")
                    Button("Забыть выученные маршруты") { model.resetLearnedRoutes() }
                        .glassButtons()
                } header: {
                    Text("Адреса из VPN")
                } footer: {
                    Text("У каждого клиента свой список, и он только пополняется. Если сайты, которые вы убрали из списка VPN, всё ещё блокируются, подключите VPN и нажмите кнопку.")
                        .foregroundStyle(.secondary)
                }
            }

            Section("Служба и запуск") {
                Toggle("Запускать Breaker при входе", isOn: Binding(
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
                Text("Если удалить службу, блокировка снимется полностью.")
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
