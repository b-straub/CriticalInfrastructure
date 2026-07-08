// The app entry point. Belongs to the Xcode app target (project.yml → xcodegen),
// which links the CriticalInfraKit library. Not part of the SwiftPM package.
import CriticalInfraKit
import SwiftUI

@main
struct CriticalInfraApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
