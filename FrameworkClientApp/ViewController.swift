//
//  ViewController.swift
//  FrameworkClientApp
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
//  Sample-app call sites updated after fork-side rename of the facade
//  class (IOSSecuritySuite -> BNRK) and its methods (amI* -> flag*).
//  See mapping header in IOSSecuritySuite.swift.

import UIKit
import IOSSecuritySuite

class RuntimeClass {
  @objc dynamic func runtimeModifiedFunction() -> Int {
    return 1
  }
}

internal class ViewController: UIViewController {
  @IBOutlet weak var result: UITextView!

  override func viewDidAppear(_ animated: Bool) {
    var message = ""

#if arch(arm64)
    message += executeChecksForArm64()
#endif

    // Runtime Check
    let test = RuntimeClass.init()
    _ = test.runtimeModifiedFunction()
    let dylds = ["UIKit"]
    let amIRuntimeHooked = BNRK.flagH2(
      dyldAllowList: dylds,
      detectionClass: RuntimeClass.self,
      selector: #selector(RuntimeClass.runtimeModifiedFunction),
      isClassMethod: false
    )

    message += """
        Jailbreak? \(BNRK.flagA())
        Jailbreak with fail msg? \(BNRK.flagAWithMsg())
        Jailbreak with failedChecks? \(BNRK.flagAWithChecks())
        Run in emulator? \(BNRK.flagB())
        Debugged? \(BNRK.flagC())
        Unexpected Launcher? \(BNRK.flagPP())
        Am I tempered with? \(BNRK.flagT(
        [.bundleID("biz.securing.FrameworkClientApp")])
        )
        Reversed? \(BNRK.flagD())
        Reversed with failedChecks? \(BNRK.flagDWithChecks())
        Am I runtime hooked? \(amIRuntimeHooked)
        Am I proxied? \(BNRK.flagE())
        """

    result.text = message
  }
}

#if arch(arm64)
extension ViewController {
  func executeChecksForArm64() -> String {
    // executeAntiHook()

    // MSHook Check
    func msHookReturnFalse(takes: Int) -> Bool {
      return false /// add breakpoint at here to test `BNRK.probeB1`
    }

    typealias FunctionType = @convention(thin) (Int) -> (Bool)
    func getSwiftFunctionAddr(_ function: @escaping FunctionType) -> UnsafeMutableRawPointer {
      return unsafeBitCast(function, to: UnsafeMutableRawPointer.self)
    }

    let funcAddr = getSwiftFunctionAddr(msHookReturnFalse)

    return """
        Am I MSHooked? \(BNRK.flagM(funcAddr))
        Application executable file hash value? \(BNRK.fingerprint() ?? "")
        IOSSecuritySuite executable file hash value? \(
        BNRK.fingerprint(.custom("IOSSecuritySuite")) ?? ""
        )
        Loaded libs? \(BNRK.listImages() ?? [])
        HasBreakpoint? \(BNRK.probeB1(funcAddr, functionSize: nil))
        Watchpoint? \(testWatchpoint())
        """
  }

  func testWatchpoint() -> Bool {

//    Uncomment these \/ and set a watch point to check the feature
//    var ptr = malloc(9)
//    var count = 3
    return BNRK.probeW1()
  }

  func executeAntiHook() {
    typealias MyPrint = @convention(thin) (Any..., String, String) -> Void
    func myPrint(_ items: Any..., separator: String = " ", terminator: String = "\n") {
      print("print has been hooked")
    }

    let myprint: MyPrint = myPrint
    let myPrintPointer = unsafeBitCast(myprint, to: UnsafeMutableRawPointer.self)
    var oldMethod: UnsafeMutableRawPointer?

    // simulating hook
    replaceSymbol(
      "$ss5print_9separator10terminatoryypd_S2StF",
      newMethod: myPrintPointer,
      oldMethod: &oldMethod
    )

    print("print hasn't been hooked")

    // antiHook
    BNRK.pinSH("$ss5print_9separator10terminatoryypd_S2StF")
    print("print has been antiHooked")
  }
}
#endif
