// swift-tools-version:5.3

// Fork rename: library / module / target renamed from IOSSecuritySuite to
// BNRuntimeKit. Source directory name retained to keep git-blame working.
import PackageDescription

let package = Package(
  name: "BNRuntimeKit",
  platforms: [
    .iOS(.v11)
  ],
  products: [
    .library(name: "BNRuntimeKit", targets: ["BNRuntimeKit"])
  ],
  targets: [
    .target(
      name: "BNRuntimeKit",
      path: "./IOSSecuritySuite",
      exclude: ["IOSSecuritySuite.h", "Info.plist"],
      resources: [.copy("Resources/PrivacyInfo.xcprivacy")]
    )
  ],
  swiftLanguageVersions: [.v4_2, .v5]
)
