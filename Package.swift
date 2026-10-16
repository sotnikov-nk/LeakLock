// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "LeakLock",
    platforms: [.macOS(.v13)],
    targets: [
        // Platform-independent logic: config, pf rule generation, parsers, decisions.
        .target(name: "LeakLockCore"),
        // Root LaunchDaemon that owns the pf anchor.
        .executableTarget(
            name: "leaklockd",
            dependencies: ["LeakLockCore"],
            linkerSettings: [.linkedFramework("SystemConfiguration")]
        ),
        // Menu-bar app.
        .executableTarget(
            name: "LeakLock",
            dependencies: ["LeakLockCore"]
        ),
        .testTarget(
            name: "LeakLockCoreTests",
            dependencies: ["LeakLockCore"]
        ),
    ]
)
