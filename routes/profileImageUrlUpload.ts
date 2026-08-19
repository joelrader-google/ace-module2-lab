/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) {
    return true // Invalid format, block for safety
  }
  const [a, b, c, d] = parts
  if (a === 127) return true // Loopback
  if (a === 10) return true // Private Class A
  if (a === 172 && b >= 16 && b <= 31) return true // Private Class B
  if (a === 192 && b === 168) return true // Private Class C
  if (a === 169 && b === 254) return true // Link-local
  if (a === 0) return true // Wildcard
  if (a >= 224) return true // Multicast & Reserved (224.0.0.0/4 and 240.0.0.0/4)
  
  // Test/Documentation/Benchmarking
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a === 198 && b >= 18 && b <= 19) return true

  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const cleanIp = ip.toLowerCase().trim()
  if (cleanIp === '::1' || cleanIp === '0:0:0:0:0:0:0:1' || cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:0') {
    return true
  }
  if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) {
    return true
  }
  if (/^fe[89ab]/i.test(cleanIp)) {
    return true
  }
  if (cleanIp.startsWith('::ffff:')) {
    const ipv4 = cleanIp.substring(7)
    if (ipv4.includes('.')) {
      return isPrivateIPv4(ipv4)
    }
  }
  return false
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }
    let hostname = parsedUrl.hostname.toLowerCase()
    if (hostname.endsWith('.')) {
      hostname = hostname.slice(0, -1)
    }
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.slice(1, -1)
    }
    if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
      return false
    }

    // Resolve the hostname to all IP addresses
    let addresses: Array<{ address: string, family: number }> = []
    try {
      addresses = await dns.promises.lookup(hostname, { all: true })
    } catch {
      // If we cannot resolve the hostname, we cannot verify its IP.
      // Do not allow fetching if we cannot resolve it.
      return false
    }

    for (const { address } of addresses) {
      if (isPrivateIPv4(address) || isPrivateIPv6(address)) {
        return false
      }
    }
    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const isSafe = await isSafeUrl(url)
          if (!isSafe) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
            return
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
