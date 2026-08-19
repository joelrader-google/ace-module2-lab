/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = typeof body.orderLinesData === 'string' ? body.orderLinesData : ''
      try {
        const blacklist = [
          /\\/,                 // block backslashes
          /'/,                  // block single quotes
          /"/,                  // block double quotes
          /`/,                  // block backticks
          /\./,                 // block dots (property access)
          /\[/,                 // block open brackets (computed property access)
          /\]/,                 // block close brackets
          /\$/,                 // block dollar sign
          /#/,                  // block hash symbol
          /\?/,                 // block question mark
          /:/,                  // block colons
          /\bthis\b/i,          // block 'this' keyword
          /constructor/i,       // block constructor
          /prototype/i,         // block prototype
          /__proto__/,          // block __proto__
          /\bprocess\b/i,       // block process
          /\bglobal/i,          // block global / globalThis
          /\brequire\b/i,       // block require
          /\bexec/i,            // block exec / execSync
          /\bspawn/i,           // block spawn / spawnSync
          /\bFunction\b/i,      // block Function
          /\beval\b/i,          // block eval
          /\bBuffer\b/i,        // block Buffer
          /mainModule/i,        // block mainModule
          /child_process/i,     // block child_process
          /\bimport\b/i,        // block import
          /fromCharCode/i,      // block fromCharCode
          /getPrototypeOf/i,    // block getPrototypeOf
          /\bReflect\b/i,       // block Reflect
          /\bProxy\b/i,         // block Proxy
          /\bString\b/i,        // block String
          /\bObject\b/i,        // block Object
          /\bArray\b/i,         // block Array
          /\barguments\b/i,     // block arguments
          /source/i,            // block source
          /atob/i,              // block atob
          /btoa/i,              // block btoa
          /RegExp/i,            // block RegExp
          /toString/i,          // block toString
          /JSON/i,              // block JSON
          /Error/i,             // block Error
          /Date/i,              // block Date
          /\bMap\b/i,           // block Map
          /\bSet\b/i,           // block Set
          /Symbol/i,            // block Symbol
          /\bconsole\b/i,       // block console
          /\bWebAssembly\b/i,   // block WebAssembly
          /\bmodule\b/i,        // block module
          /\bexports\b/i,       // block exports
          /\bperformance\b/i,   // block performance
          /\bsetTimeout\b/i,    // block setTimeout
          /\bsetInterval\b/i,   // block setInterval
          /\bsetImmediate\b/i,  // block setImmediate
          /\bclearTimeout\b/i,  // block clearTimeout
          /\bclearInterval\b/i, // block clearInterval
          /\bclearImmediate\b/i, // block clearImmediate
          /\bfetch\b/i,         // block fetch
          /\bIntl\b/i,          // block Intl
          /\bPromise\b/i,       // block Promise
          /define/i             // block defineProperty, __defineGetter__, etc.
        ]

        if (blacklist.some((regex) => regex.test(orderLinesData))) {
          res.status(400)
          next(new Error('Invalid order lines data.'))
          return
        }

        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
