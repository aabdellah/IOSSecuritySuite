//
//  I3.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation

internal class I3 {
  static func amIRunInEmulator() -> Bool {
    return checkCompile() || checkRuntime()
  }

  private static func checkRuntime() -> Bool {
    return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
  }

  private static func checkCompile() -> Bool {
#if targetEnvironment(simulator)
    return true
#else
    return false
#endif
  }
}
