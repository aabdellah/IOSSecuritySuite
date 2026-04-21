Pod::Spec.new do |s|
  # Fork rename: module consumed as BNRuntimeKit. Upstream is still
  # securing/IOSSecuritySuite and was originally called IOSSecuritySuite.
  # Renamed to reduce fingerprint visibility in the shipped Mach-O of
  # consumer apps (class-dump / Hopper / Ghidra no longer surface a
  # string that names the anti-tampering purpose of this framework).
  s.name         = "BNRuntimeKit"
  s.version      = "2.2.0"
  s.summary      = "Runtime platform context inspector (iOS)."
  s.homepage     = "https://github.com/aabdellah/IOSSecuritySuite"
  s.license      = "custom EULA"
  s.author       = "Wojciech Reguła"
  s.social_media_url = "https://x.com/_r3ggi"
  s.platform     = :ios, "12.0"
  s.ios.frameworks = 'UIKit', 'Foundation'
  s.source       = { :git => "https://github.com/aabdellah/IOSSecuritySuite.git", :tag => "#{s.version}" }
  s.source_files  = "IOSSecuritySuite/*.swift"
  s.resource_bundles = {'BNRuntimeKitPrivacy' => ['IOSSecuritySuite/Resources/PrivacyInfo.xcprivacy']}
  s.swift_version = '5.0'
  s.requires_arc = true
  s.pod_target_xcconfig = { 'SWIFT_VERSION' => '5.0' }
end
