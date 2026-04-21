//
//  IOSSecuritySuite.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
//  ---------------------------------------------------------------------------
//  Fork-side obfuscation rename (source-only mapping; none of the original
//  identifiers below ship in the compiled binary):
//
//    IOSSecuritySuite   (public class)         -> BNRK
//    amIJailbroken                             -> flagA
//    amIJailbrokenWithFailMessage              -> flagAWithMsg
//    amIJailbrokenWithFailedChecks             -> flagAWithChecks
//    amIRunInEmulator                          -> flagB
//    amIDebugged                               -> flagC
//    denyDebugger                              -> pinDbg
//    isParentPidUnexpected                     -> flagPP
//    amITampered                               -> flagT
//    amIReverseEngineered                      -> flagD
//    amIReverseEngineeredWithFailedChecks      -> flagDWithChecks
//    amIRuntimeHooked(dyldWhiteList:)          -> flagH1        (deprecated overload)
//    amIRuntimeHooked(dyldAllowList:)          -> flagH2        (current overload)
//    amIProxied                                -> flagE
//    amIInLockdownMode                         -> flagL
//    amIMSHooked                               -> flagM
//    denyMSHook                                -> pinMS
//    denySymbolHook                            -> pinSH
//    getMachOFileHashValue                     -> fingerprint
//    findLoadedDylibs                          -> listImages
//    hasBreakpointAt                           -> probeB1
//    hasWatchpoint                             -> probeW1
//  ---------------------------------------------------------------------------
//
//swiftlint:disable line_length

import Foundation
import MachO

/// Main class that encompasses library functionalities.
/// Originally named `IOSSecuritySuite` — renamed to `BNRK` for consumer-side
/// obfuscation. See mapping table at the top of this file.
@objc
@available(iOSApplicationExtension, unavailable)
public class BNRK: NSObject {
  /// Originally `amIJailbroken` — jailbreak true/false.
  @objc
  public static func flagA() -> Bool {
    return JailbreakChecker.amIJailbroken()
  }

  /// Originally `amIJailbrokenWithFailMessage` — jailbreak status + first-fail message.
  public static func flagAWithMsg() -> (jailbroken: Bool, failMessage: String) {
    return JailbreakChecker.amIJailbrokenWithFailMessage()
  }

  /// Originally `amIJailbrokenWithFailedChecks` — jailbreak status + list of failed checks.
  public static func flagAWithChecks() -> (jailbroken: Bool,
                                            failedChecks: [FailedCheckType]) {
    return JailbreakChecker.amIJailbrokenWithFailedChecks()
  }

  /// Originally `amIRunInEmulator`.
  @objc
  public static func flagB() -> Bool {
    return EmulatorChecker.amIRunInEmulator()
  }

  /// Originally `amIDebugged`.
  @objc
  public static func flagC() -> Bool {
    return DebuggerChecker.amIDebugged()
  }

  /// Originally `denyDebugger` — PT_DENY_ATTACH installer.
  @objc
  public static func pinDbg() {
    return DebuggerChecker.denyDebugger()
  }

  /// Originally `isParentPidUnexpected`.
  public static func flagPP() -> Bool {
    return DebuggerChecker.isParentPidUnexpected()
  }

  /// Originally `amITampered`.
  public static func flagT(_ checks: [FileIntegrityCheck]) -> FileIntegrityCheckResult {
    return IntegrityChecker.amITampered(checks)
  }

  /// Originally `amIReverseEngineered`.
  @objc
  public static func flagD() -> Bool {
    return ReverseEngineeringToolsChecker.amIReverseEngineered()
  }

  /// Originally `amIReverseEngineeredWithFailedChecks`.
  public static func flagDWithChecks() -> (reverseEngineered: Bool,
                                            failedChecks: [FailedCheckType]) {
    return ReverseEngineeringToolsChecker.amIReverseEngineeredWithFailedChecks()
  }

  /// Originally `amIRuntimeHooked(dyldWhiteList:)` — deprecated overload.
  @available(*, deprecated, renamed: "flagH2(dyldAllowList:detectionClass:selector:isClassMethod:)")
  @objc
  public static func flagH1(
    dyldWhiteList: [String],
    detectionClass: AnyClass,
    selector: Selector,
    isClassMethod: Bool
  ) -> Bool {
    return RuntimeHookChecker.amIRuntimeHook(
      dyldAllowList: dyldWhiteList,
      detectionClass: detectionClass,
      selector: selector,
      isClassMethod: isClassMethod
    )
  }

  /// Originally `amIRuntimeHooked(dyldAllowList:)` — current overload.
  @objc
  public static func flagH2(
    dyldAllowList: [String],
    detectionClass: AnyClass,
    selector: Selector,
    isClassMethod: Bool
  ) -> Bool {
    return RuntimeHookChecker.amIRuntimeHook(
      dyldAllowList: dyldAllowList,
      detectionClass: detectionClass,
      selector: selector,
      isClassMethod: isClassMethod
    )
  }

  /// Originally `amIProxied`.
  @objc
  public static func flagE() -> Bool {
    return ProxyChecker.amIProxied()
  }

  /// Originally `amIInLockdownMode` — iOS 16+ only.
  @available(iOS 16, *)
  public static func flagL() -> Bool {
    return ModesChecker.amIInLockdownMode()
  }
}

#if arch(arm64)
@available(iOSApplicationExtension, unavailable)
public extension BNRK {
  /// Originally `amIMSHooked` — MSHook check for a function address.
  static func flagM(_ functionAddress: UnsafeMutableRawPointer) -> Bool {
    return MSHookFunctionChecker.amIMSHooked(functionAddress)
  }

  /// Originally `denyMSHook` — returns original trampoline if MSHook patched the function.
  static func pinMS(_ functionAddress: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
    return MSHookFunctionChecker.denyMSHook(functionAddress)
  }

  /// Originally `denySymbolHook` — fishhook rebind.
  static func pinSH(_ symbol: String) {
    FishHookChecker.denyFishHook(symbol)
  }

  /// Originally `denySymbolHook(_:at:imageSlide:)` — image-scoped fishhook rebind.
  static func pinSH(
    _ symbol: String,
    at image: UnsafePointer<mach_header>,
    imageSlide slide: Int
  ) {
    FishHookChecker.denyFishHook(symbol, at: image, imageSlide: slide)
  }

  /// Originally `getMachOFileHashValue` — SHA256 of the image's `__TEXT.__text`.
  static func fingerprint(_ target: IntegrityCheckerImageTarget = .default) -> String? {
    return IntegrityChecker.getMachOFileHashValue(target)
  }

  /// Originally `findLoadedDylibs`.
  static func listImages(_ target: IntegrityCheckerImageTarget = .default) -> [String]? {
    return IntegrityChecker.findLoadedDylibs(target)
  }

  /// Originally `hasBreakpointAt`.
  static func probeB1(_ functionAddr: UnsafeRawPointer, functionSize: vm_size_t?) -> Bool {
    return DebuggerChecker.hasBreakpointAt(functionAddr, functionSize: functionSize)
  }

  /// Originally `hasWatchpoint`.
  static func probeW1() -> Bool {
    return DebuggerChecker.hasWatchpoint()
  }
}
#endif
