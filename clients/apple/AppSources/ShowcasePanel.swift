import CriticalInfraKit
import SwiftUI

/// The provisioning & security **showcase**: the four capability areas as guided step cards.
/// Safe/read-only steps run inline (live output + verdict); interactive/destructive steps launch
/// Terminal. macOS-only — on iOS it shows an unavailable state.
struct ShowcasePanel: View {
    @Bindable var model: AppModel

    var body: some View {
        #if os(macOS)
        MacShowcase(model: model)
        #else
        ContentUnavailableView(
            "Provisioning runs on macOS",
            systemImage: "desktopcomputer",
            description: Text("The showcase drives the provisioning scripts, which need a Mac terminal and USB tools.")
        )
        #endif
    }
}

#if os(macOS)
private struct MacShowcase: View {
    @Bindable var model: AppModel
    @State private var controller = ShowcaseController()
    @State private var selectedPort: String = ShowcaseStepCard.autoPort
    @State private var ports: [String] = []

    private var repoPath: String { model.config.repoPath }
    private var repoResolved: Bool {
        !repoPath.isEmpty && FileManager.default.fileExists(atPath: repoPath + "/provision/lib.sh")
    }

    var body: some View {
        Group {
            if !repoResolved {
                ContentUnavailableView {
                    Label("Set the repo path", systemImage: "folder.badge.questionmark")
                } description: {
                    Text("Choose your CriticalInfrastructure checkout so the showcase can find provision/*.sh.")
                } actions: {
                    Button("Choose repo folder…") { chooseRepo() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                CenteredColumn(maxWidth: 640) {
                    portPicker
                    ForEach(ShowcaseCatalog.areas) { area in
                        AreaSection(area: area, model: model, controller: controller, port: portArg)
                    }
                }
            }
        }
        .onAppear(perform: refreshPorts)
    }

    private var portArg: String? {
        selectedPort == ShowcaseStepCard.autoPort ? nil : selectedPort
    }

    private func chooseRepo() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Select repo"
        if panel.runModal() == .OK, let url = panel.url {
            model.config.repoPath = url.path
            model.config.save()
        }
    }

    private var portPicker: some View {
        GroupBox {
            HStack {
                Picker("USB port", selection: $selectedPort) {
                    Text("Auto-detect").tag(ShowcaseStepCard.autoPort)
                    ForEach(ports, id: \.self) { Text($0).tag($0) }
                }
                Button {
                    refreshPorts()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Rescan USB serial ports")
            }
        } label: {
            Label("Board connection", systemImage: "cable.connector")
        }
    }

    private func refreshPorts() {
        let devs = (try? FileManager.default.contentsOfDirectory(atPath: "/dev")) ?? []
        ports = devs
            .filter { $0.hasPrefix("cu.usbmodem") || $0.hasPrefix("cu.usbserial") }
            .map { "/dev/" + $0 }
            .sorted()
        if !ports.contains(selectedPort) { selectedPort = ShowcaseStepCard.autoPort }
    }
}

private struct AreaSection: View {
    let area: ShowcaseArea
    @Bindable var model: AppModel
    let controller: ShowcaseController
    let port: String?

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                Text(area.blurb)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 4)
                ForEach(Array(area.steps.enumerated()), id: \.element.id) { idx, step in
                    if idx > 0 { Divider().padding(.vertical, 6) }
                    ShowcaseStepCard(step: step, model: model, controller: controller, port: port)
                }
            }
        } label: {
            Label(area.title, systemImage: area.icon)
                .font(.headline)
        }
    }
}

struct ShowcaseStepCard: View {
    static let autoPort = "__auto__"

    let step: ShowcaseStep
    @Bindable var model: AppModel
    let controller: ShowcaseController
    let port: String?

    private var invocation: ScriptInvocation? {
        resolveShowcaseStep(step, repoPath: model.config.repoPath, config: model.config, port: port)
    }
    private var isThisRunning: Bool { controller.runningStepID == step.id }
    private var showsResult: Bool { controller.resultStepID == step.id }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(step.title).font(.body.weight(.semibold))
                Spacer()
                ModeTag(mode: step.mode)
            }
            Text(step.rationale)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let hint = step.terminalHint {
                Label(hint, systemImage: step.mode == .manual ? "hand.point.up.left" : "exclamationmark.triangle")
                    .font(.caption2)
                    .foregroundStyle(step.mode == .manual ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            actionRow

            if showsResult {
                RunOutputView(text: controller.output)
                VerdictBadge(verdict: controller.verdict)
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder private var actionRow: some View {
        HStack(spacing: 8) {
            switch step.mode {
            case .inline:
                if isThisRunning {
                    Button(role: .destructive) { controller.cancel() } label: {
                        Label("Cancel", systemImage: "stop.fill")
                    }
                    .buttonStyle(.bordered)
                } else {
                    Button {
                        if let inv = invocation {
                            controller.runInline(inv, stepID: step.id, verdictMap: step.verdict)
                        }
                    } label: {
                        Label("Run", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(invocation == nil || controller.isRunning)
                }
                copyButton
            case .terminal:
                Button {
                    if let inv = invocation { TerminalLauncher.run(inv, repoPath: model.config.repoPath) }
                } label: {
                    Label("Run in Terminal", systemImage: "terminal")
                }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
                .disabled(invocation == nil)
                copyButton
            case .manual:
                EmptyView()
            }
        }
        .controlSize(.regular)
        .if(isThisRunning) { $0.overlay(alignment: .trailing) { ProgressView().controlSize(.small) } }
    }

    @ViewBuilder private var copyButton: some View {
        if let inv = invocation {
            Button {
                TerminalLauncher.copyToClipboard(inv.display)
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)
            .help("Copy the command")
        }
    }
}

private struct ModeTag: View {
    let mode: RunMode

    var body: some View {
        let (text, icon, tint): (String, String, Color) = {
            switch mode {
            case .inline: return ("runs in app", "play.circle", .green)
            case .terminal: return ("terminal", "terminal", .orange)
            case .manual: return ("manual", "hand.point.up.left", Color.secondary)
            }
        }()
        Label(text, systemImage: icon)
            .font(.caption2.weight(.medium))
            .foregroundStyle(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(tint.opacity(0.12), in: Capsule())
    }
}

private struct RunOutputView: View {
    let text: String

    var body: some View {
        ScrollView {
            Text(text.isEmpty ? "…" : text)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
        }
        .frame(maxHeight: 220)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct VerdictBadge: View {
    let verdict: Verdict

    var body: some View {
        switch verdict {
        case .pass:
            badge("PASS", "checkmark.seal.fill", .green)
        case .fail:
            badge("FAIL", "xmark.seal.fill", .red)
        case .warn(let note):
            VStack(alignment: .leading, spacing: 2) {
                badge("CHECK", "exclamationmark.triangle.fill", .orange)
                Text(note).font(.caption2).foregroundStyle(.secondary)
            }
        case .unknown:
            EmptyView()
        }
    }

    private func badge(_ text: String, _ icon: String, _ tint: Color) -> some View {
        Label(text, systemImage: icon)
            .font(.caption.weight(.bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(tint, in: Capsule())
    }
}

private extension View {
    @ViewBuilder func `if`<T: View>(_ cond: Bool, _ transform: (Self) -> T) -> some View {
        if cond { transform(self) } else { self }
    }
}
#endif
