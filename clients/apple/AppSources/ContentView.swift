import CriticalInfraKit
import SwiftUI
#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

struct ContentView: View {
    @Bindable var model: AppModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(title)
                .inlineNavTitle()
                .toolbar {
                    if model.showShowcase || model.showConfig {
                        ToolbarItem(placement: .navigation) {
                            Button {
                                model.showShowcase = false
                                model.showConfig = false
                            } label: {
                                Label("Home", systemImage: "house")
                            }
                            .help("Back to dashboard")
                        }
                    }
                    if model.activeRole != nil || model.hardwareMode {
                        ToolbarItem {
                            Button {
                                model.switchIdentity()
                            } label: {
                                Label("Switch", systemImage: "arrow.left.arrow.right")
                            }
                        }
                    }
                    #if os(macOS)
                    ToolbarItem {
                        Button {
                            model.showShowcase.toggle()
                            if model.showShowcase { model.showConfig = false }
                        } label: {
                            Image(systemName: "wrench.and.screwdriver")
                        }
                        .help("Provisioning & security showcase")
                    }
                    #endif
                    ToolbarItem {
                        Button {
                            model.showConfig.toggle()
                            if model.showConfig { model.showShowcase = false }
                        } label: {
                            Image(systemName: "gearshape")
                        }
                    }
                }
        }
        #if os(macOS)
        .frame(minWidth: 500, minHeight: 480)
        #endif
    }

    @ViewBuilder private var content: some View {
        if model.showShowcase {
            ShowcasePanel(model: model)
        } else if model.showConfig {
            ConfigForm(model: model)
        } else if model.hardwareMode {
            HardwarePanel(model: model)
        } else if let role = model.activeRole {
            if role == .supervisor {
                SupervisorPanel(model: model)
            } else {
                OperatorPanel(model: model, role: role)
            }
        } else {
            IdentityPicker(model: model)
        }
    }

    private var title: String {
        if model.showShowcase { return "Showcase" }
        if model.showConfig { return "Settings" }
        if model.hardwareMode { return "Hardware Key" }
        if let role = model.activeRole { return role.rawValue }
        return "Critical Infra"
    }
}

// MARK: - Settings

private struct ConfigForm: View {
    @Bindable var model: AppModel

    var body: some View {
        Form {
            Section("Device") {
                Picker("Transport", selection: $model.config.transport) {
                    Text("Wi-Fi (UDP)").tag(TransportKind.udp)
                    Text("Bluetooth (BLE)").tag(TransportKind.ble)
                }
                switch model.config.transport {
                case .udp:
                    TextField("Device IP", text: $model.config.host)
                        .autocorrectionDisabled()
                        .platformFieldKeyboard(.numeric)
                case .ble:
                    TextField("Device name", text: $model.config.bleName)
                        .autocorrectionDisabled()
                }
                TextField("X25519 (ROM) key", text: $model.config.espX25519PubHex)
                    .font(.body.monospaced())
                    .autocorrectionDisabled()
                    .platformFieldKeyboard(.ascii)
                TextField("Ed25519 sig key", text: $model.config.espSigPubHex)
                    .font(.body.monospaced())
                    .autocorrectionDisabled()
                    .platformFieldKeyboard(.ascii)
            }

            Section {
                TextField("This device's name", text: $model.config.deviceName, prompt: Text(Command.localDeviceLabel()))
                    .autocorrectionDisabled()
            } header: {
                Text("Identity")
            } footer: {
                Text("Used as the key label when this device enrolls a role (LIST_ROLES shows role@\(model.resolvedDeviceLabel)). Firmware charset [A-Za-z0-9._-], 16 chars.")
            }

            if let hw = model.hardwareKeyPubHex {
                Section {
                    TextField(
                        "Token nickname",
                        text: Binding(
                            get: { model.config.tokenNicknames[hw] ?? "" },
                            set: { model.setTokenNickname($0, forPubkey: hw) }
                        ),
                        prompt: Text(model.hardwareCertName ?? "e.g. ESP32_S3_Master")
                    )
                    .autocorrectionDisabled()
                    Text(hw)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                } header: {
                    Text("Inserted hardware key")
                } footer: {
                    Text("The card carries no editable name, so this nickname (kept per key) is what shows in the app and prefills the key label when you provision this token as a role.")
                }
            }
            #if os(macOS)
            Section("Provisioning") {
                HStack {
                    Text(model.config.repoPath.isEmpty ? "No repo selected" : model.config.repoPath)
                        .font(.caption.monospaced())
                        .foregroundStyle(model.config.repoPath.isEmpty ? .secondary : .primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("Choose…") { chooseRepo() }
                }
                if !model.config.repoPath.isEmpty && !repoValid {
                    Label("provision/lib.sh not found here", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            #endif
            Section {
                Button("Save") { model.saveConfig() }
                    .disabled(model.config.needsSetup)
            }
        }
        .formStyle(.grouped)
    }

    #if os(macOS)
    private var repoValid: Bool {
        FileManager.default.fileExists(atPath: model.config.repoPath + "/provision/lib.sh")
    }

    private func chooseRepo() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Select repo"
        if panel.runModal() == .OK, let url = panel.url {
            model.config.repoPath = url.path
            model.config.save()   // persist without the needsSetup side-effect (keeps Settings open)
        }
    }
    #endif
}

// MARK: - Identity picker  (a: register supervisor · c: pick identity)

private struct IdentityPicker: View {
    @Bindable var model: AppModel

    var body: some View {
        if model.availableRoles.isEmpty && model.hardwareKeyPubHex == nil {
            ContentUnavailableView {
                Label("No identity on this device", systemImage: "person.crop.circle.badge.questionmark")
            } description: {
                Text("Create the Supervisor key in this device's Secure Enclave (then bake its public key into the firmware), or insert a PIV hardware key.")
            } actions: {
                Button("Register Supervisor") { model.registerSupervisor() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                Button("Rescan for hardware key") { model.refreshHardware() }
                    .buttonStyle(.bordered)
            }
        } else {
            CenteredColumn(maxWidth: 460) {
                VStack(spacing: 4) {
                    Text("Choose an identity").font(.title2.bold())
                    Text("A Secure Enclave key, or an inserted hardware key.")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)

                VStack(spacing: 10) {
                    ForEach(model.availableRoles, id: \.self) { role in
                        IdentityCard(role: role, deviceLabel: model.resolvedDeviceLabel) {
                            model.select(role)
                        }
                    }
                    if let hw = model.hardwareKeyPubHex {
                        HardwareCard(
                            pubkey: hw,
                            keyName: model.hardwareKeyName,
                            onSupervisor: { model.useHardwareKeyAsSupervisor() },
                            onOperational: { model.useHardwareKey() }
                        )
                    }
                }

                HStack {
                    if !model.hasSupervisor {
                        Button("Register Supervisor") { model.registerSupervisor() }
                            .buttonStyle(.bordered)
                    }
                    Spacer()
                    Button { model.refreshHardware() } label: {
                        Label("Rescan", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                }

                if let resp = model.lastResponse {
                    ResponseCard(text: resp)
                }
            }
        }
    }
}

// MARK: - Supervisor  (role CRUD only)

private struct SupervisorPanel: View {
    @Bindable var model: AppModel
    @State private var externalPubkey = ""
    @State private var externalRole: Role = .admin
    @State private var externalLabel = ""

    var body: some View {
        CenteredColumn {
            RoleHero(role: .supervisor)

            if let pk = model.activePublicKeyHex {
                GroupBox {
                    KeyCard(pubkey: pk)
                } label: {
                    Label(
                        model.activeIsHardware
                            ? "Hardware supervisor key “\(model.hardwareKeyName ?? "unnamed")” — bake as SUPERVISOR_PUBKEY"
                            : "Supervisor key — bake as SUPERVISOR_PUBKEY",
                        systemImage: model.activeIsHardware ? "key.card" : "cpu"
                    )
                }
            }

            GroupBox {
                VStack(spacing: 0) {
                    ForEach(Array(Role.operational.enumerated()), id: \.element) { index, role in
                        if index > 0 { Divider() }
                        RoleManageRow(
                            role: role,
                            isRegistered: model.availableRoles.contains(role),
                            onRegister: { model.registerRole(role) },
                            onRevoke: { model.revokeRole(role) }
                        )
                    }
                }
            } label: {
                HStack {
                    Label("Roles", systemImage: "person.2.fill")
                    Spacer()
                    Button { model.listRoles() } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                }
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Provision a P-256 public key from a hardware key or another device — the private key stays where it lives.")
                        .font(.caption).foregroundStyle(.secondary)
                    TextField("Public key (66 hex)", text: $externalPubkey)
                        .hexFieldStyle()
                    TextField("Key label — device or token name (required)", text: $externalLabel)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                    if let hw = model.hardwareKeyPubHex {
                        Button {
                            externalPubkey = hw
                            // Prefill the label from the token's display name — the
                            // Settings nickname if set, else its certificate subject.
                            if externalLabel.isEmpty, let name = model.hardwareKeyName {
                                externalLabel = Command.sanitizeLabel(name)
                            }
                        } label: {
                            Label("Use inserted hardware key", systemImage: "key.card")
                        }
                        .buttonStyle(.borderless)
                        .controlSize(.small)
                    }
                    HStack {
                        Picker("Role", selection: $externalRole) {
                            ForEach(Role.operational, id: \.self) { Text($0.rawValue).tag($0) }
                        }
                        .labelsHidden()
                        .fixedSize()
                        Spacer()
                        Button("Provision") {
                            model.provisionExternal(
                                pubkeyHex: externalPubkey, as: externalRole,
                                label: externalLabel)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(
                            externalPubkey.count != 66
                                || externalLabel.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            } label: {
                Label("Provision external / hardware key", systemImage: "externaldrive.badge.plus")
            }

            if let resp = model.lastResponse {
                ResponseCard(text: resp)
            }
        }
        .busyOverlay(model.busy)
    }
}

// MARK: - Operational roles  (Admin / Operator / Observer)

private struct OperatorPanel: View {
    @Bindable var model: AppModel
    let role: Role

    private var commands: [CommandItem] {
        var c = [CommandItem(title: "Read Sensor", icon: "thermometer.medium", tint: .green, cmd: Command.readSensor)]
        if role.operationalRank >= 2 {
            c.append(CommandItem(title: "Threshold 20°", icon: "arrow.down.to.line", tint: .orange, cmd: Command.setThreshold(20)))
            c.append(CommandItem(title: "Threshold 30°", icon: "arrow.up.to.line", tint: .orange, cmd: Command.setThreshold(30)))
        }
        if role.operationalRank >= 3 {
            c.append(CommandItem(title: "Clear Alarm", icon: "bell.slash.fill", tint: .red, cmd: Command.clearAlarm))
            c.append(CommandItem(title: "Test Alarm", icon: "bell.badge.fill", tint: .red, cmd: Command.colorRed))
        }
        return c
    }

    var body: some View {
        CenteredColumn {
            RoleHero(role: role)

            GroupBox {
                CommandGrid(commands: commands) { model.send($0) }
            } label: {
                Label("Commands", systemImage: "square.grid.2x2.fill")
            }

            if let resp = model.lastResponse {
                ResponseCard(text: resp)
            }
        }
        .busyOverlay(model.busy)
    }
}

// MARK: - Reusable components

struct CenteredColumn<Content: View>: View {
    var maxWidth: CGFloat = 560
    @ViewBuilder let content: Content
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var hSize
    #endif

    private var pad: CGFloat {
        #if os(iOS)
        hSize == .compact ? 16 : 24   // tighter gutters on iPhone
        #else
        24
        #endif
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) { content }
                .frame(maxWidth: maxWidth)
                .frame(maxWidth: .infinity)
                .padding(pad)
        }
        .scrollDismissesKeyboard(.interactively)
    }
}

// MARK: - Cross-platform view helpers

extension View {
    /// Inline navigation title on iOS/iPadOS (saves the large-title vertical space);
    /// no-op on macOS where the modifier doesn't exist.
    @ViewBuilder func inlineNavTitle() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }

    /// A monospaced key/hex field with the right mobile keyboard hygiene.
    @ViewBuilder func hexFieldStyle() -> some View {
        self.font(.callout.monospaced())
            .textFieldStyle(.roundedBorder)
            .autocorrectionDisabled()
            .platformFieldKeyboard(.ascii)
    }

    /// Set an appropriate iOS keyboard + no autocapitalization; no-op on macOS
    /// (where `UIKeyboardType` doesn't exist).
    @ViewBuilder func platformFieldKeyboard(_ kind: FieldKeyboard) -> some View {
        #if os(iOS)
        switch kind {
        case .ascii:
            self.keyboardType(.asciiCapable).textInputAutocapitalization(.never)
        case .numeric:
            self.keyboardType(.numbersAndPunctuation).textInputAutocapitalization(.never)
        }
        #else
        self
        #endif
    }
}

/// Cross-platform keyboard hint (maps to `UIKeyboardType` on iOS, ignored on macOS).
enum FieldKeyboard { case ascii, numeric }

private struct IdentityCard: View {
    let role: Role
    var deviceLabel: String = ""
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                RoleBadge(role: role, size: 44)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(role.rawValue).font(.headline)
                        if !deviceLabel.isEmpty {
                            Text(deviceLabel)
                                .font(.caption.weight(.medium))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1)
                                .background(.quaternary, in: Capsule())
                        }
                    }
                    Text(role.blurb).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(14)
            .background(
                hover ? AnyShapeStyle(role.tint.opacity(0.12)) : AnyShapeStyle(.quaternary.opacity(0.5)),
                in: RoundedRectangle(cornerRadius: 12, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(hover ? role.tint.opacity(0.5) : .clear, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .animation(.easeOut(duration: 0.12), value: hover)
    }
}

/// One row in the Supervisor's Roles list: shows the role's state with an inline
/// Register (if absent) or Revoke (if present) action — CRUD lives on the row.
private struct RoleManageRow: View {
    let role: Role
    let isRegistered: Bool
    let onRegister: () -> Void
    let onRevoke: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            RoleBadge(role: role, size: 34)
                .opacity(isRegistered ? 1 : 0.35)
                .grayscale(isRegistered ? 0 : 1)
            VStack(alignment: .leading, spacing: 1) {
                Text(role.rawValue).font(.body.weight(.medium))
                Text(isRegistered ? "Registered" : "Not registered")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if isRegistered {
                Button("Revoke", role: .destructive, action: onRevoke)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .tint(.red)
            } else {
                Button("Register", action: onRegister)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .tint(role.tint)
            }
        }
        .padding(.vertical, 8)
    }
}

private struct CommandButton: View {
    let title: String
    let icon: String
    let tint: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: icon)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)   // roomier tap target on touch
        }
        .buttonStyle(.bordered)
        .controlSize(.large)
        .tint(tint)
    }
}

/// A command model shared by the operator / hardware panels.
struct CommandItem: Identifiable {
    let id = UUID()
    let title: String
    let icon: String
    let tint: Color
    let cmd: String
}

/// Commands laid out in an adaptive grid: two columns where there's room
/// (iPad / Mac / landscape), a single column on a compact iPhone width.
private struct CommandGrid: View {
    let commands: [CommandItem]
    let run: (String) -> Void
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var hSize
    #endif

    private var columns: [GridItem] {
        #if os(iOS)
        let count = hSize == .compact ? 1 : 2
        #else
        let count = 2
        #endif
        return Array(repeating: GridItem(.flexible(), spacing: 10), count: count)
    }

    var body: some View {
        LazyVGrid(columns: columns, spacing: 10) {
            ForEach(commands) { c in
                CommandButton(title: c.title, icon: c.icon, tint: c.tint) { run(c.cmd) }
            }
        }
    }
}

private struct KeyCard: View {
    let pubkey: String

    var body: some View {
        HStack(spacing: 8) {
            Text(pubkey)
                .font(.callout.monospaced())
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Button {
                copy(pubkey)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy public key")
        }
    }

    private func copy(_ s: String) {
        #if canImport(AppKit)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        #elseif canImport(UIKit)
        UIPasteboard.general.string = s
        #endif
    }
}

private struct ResponseCard: View {
    let text: String

    var body: some View {
        GroupBox {
            Text(text)
                .font(.callout.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Response", systemImage: "text.bubble")
        }
    }
}

private extension View {
    func busyOverlay(_ busy: Bool) -> some View {
        overlay {
            if busy {
                ProgressView()
                    .controlSize(.large)
                    .padding(24)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
            }
        }
    }
}

// MARK: - Hardware key

private struct HardwareCard: View {
    let pubkey: String
    var keyName: String?
    let onSupervisor: () -> Void
    let onOperational: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 14) {
                Image(systemName: "key.card.fill")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 44, height: 44)
                    .background(Color.indigo.gradient, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .shadow(color: .indigo.opacity(0.35), radius: 4, y: 2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(keyName ?? "Hardware Key").font(.headline)
                    Text("PIV smart card — PIN per command").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }

            KeyCard(pubkey: pubkey)

            HStack(spacing: 10) {
                Button(action: onSupervisor) {
                    Label("Act as Supervisor", systemImage: "key.horizontal.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.purple)
                Button(action: onOperational) {
                    Label("Operational", systemImage: "person.badge.shield.checkmark.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(.indigo)
            }
            .controlSize(.large)
        }
        .padding(14)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct HardwarePanel: View {
    @Bindable var model: AppModel

    private let commands: [CommandItem] = [
        CommandItem(title: "Identify (WHOAMI)", icon: "person.text.rectangle", tint: .indigo, cmd: Command.whoami),
        CommandItem(title: "Read Sensor", icon: "thermometer.medium", tint: .green, cmd: Command.readSensor),
        CommandItem(title: "Threshold 20°", icon: "arrow.down.to.line", tint: .orange, cmd: Command.setThreshold(20)),
        CommandItem(title: "Threshold 30°", icon: "arrow.up.to.line", tint: .orange, cmd: Command.setThreshold(30)),
        CommandItem(title: "Clear Alarm", icon: "bell.slash.fill", tint: .red, cmd: Command.clearAlarm),
        CommandItem(title: "Test Alarm", icon: "bell.badge.fill", tint: .red, cmd: Command.colorRed)
    ]

    var body: some View {
        CenteredColumn {
            HStack(spacing: 14) {
                Image(systemName: "key.card.fill")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 54, height: 54)
                    .background(Color.indigo.gradient, in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                    .shadow(color: .indigo.opacity(0.35), radius: 4, y: 2)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Hardware Key").font(.title2.bold())
                    Text("PIV smart card — the device decides the role")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if let pk = model.hardwareKeyPubHex {
                GroupBox {
                    KeyCard(pubkey: pk)
                } label: {
                    Label(
                        "Card key “\(model.hardwareKeyName ?? "unnamed")” — provision as a role",
                        systemImage: "cpu"
                    )
                }
            }

            GroupBox {
                CommandGrid(commands: commands) { model.send($0) }
            } label: {
                Label("Commands", systemImage: "square.grid.2x2.fill")
            }

            if let resp = model.lastResponse {
                ResponseCard(text: resp)
            }
        }
        .busyOverlay(model.busy)
    }
}

#Preview {
    ContentView(model: AppModel())
}
