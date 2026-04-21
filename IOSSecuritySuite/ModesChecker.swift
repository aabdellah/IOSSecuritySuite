//
//  M1.swift
//  IOSSecuritySuite
//
//  Created by Wojciech Reguła on 28/03/2024.
//  Copyright © 2024 wregula. All rights reserved.
//

import Foundation

internal class M1 {
  
  static func amIInLockdownMode() -> Bool {
    return UserDefaults.standard.bool(forKey: "LDMGlobalEnabled")
  }
  
}
