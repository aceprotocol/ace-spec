// swift-tools-version: 6.2
// ACE cross-SDK interop harness — Swift side. Depends on the local sdk-swift checkout.
import PackageDescription

let package = Package(
    name: "ace-interop",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(path: "../../../sdk-swift"),
    ],
    targets: [
        .executableTarget(
            name: "ACEInterop",
            dependencies: [.product(name: "ACE", package: "sdk-swift")],
            path: "Sources/ACEInterop"
        ),
    ]
)
