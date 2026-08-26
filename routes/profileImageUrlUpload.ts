/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import { isIP } from 'node:net'
import { URL } from 'node:url'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  let normalizedIp = ip.trim().toLowerCase()
  if (normalizedIp.startsWith('::ffff:')) {
    normalizedIp = normalizedIp.substring(7)
  }

  if (isIP(normalizedIp) === 4) {
    const parts = normalizedIp.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) return true
    
    // 0.0.0.0/8
    if (parts[0] === 0) return true
    // 127.0.0.0/8
    if (parts[0] === 127) return true
    // 10.0.0.0/8
    if (parts[0] === 10) return true
    // 100.64.0.0/10
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true
    // 169.254.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return true
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
    // 192.0.0.0/24
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return true
    // 192.0.2.0/24
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true
    // 198.18.0.0/15
    if (parts[0] === 198 && parts[1] >= 18 && parts[1] <= 19) return true
    // 198.51.100.0/24
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true
    // 203.0.113.0/24
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true
    // 224.0.0.0/4
    if (parts[0] >= 224 && parts[0] <= 239) return true
    // 240.0.0.0/4
    if (parts[0] >= 240) return true
  } else if (isIP(normalizedIp) === 6) {
    // ::1
    if (normalizedIp === '::1' || normalizedIp === '0:0:0:0:0:0:0:1') return true
    // ::
    if (normalizedIp === '::' || normalizedIp === '0:0:0:0:0:0:0:0') return true
    // fe80::/10 (link-local)
    if (normalizedIp.startsWith('fe80:')) return true
    // fc00::/7 (unique local address)
    if (normalizedIp.startsWith('fc') || normalizedIp.startsWith('fd')) return true
  }
  return false
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlString)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname
    if (!hostname) return false

    if (isIP(hostname)) {
      if (isPrivateIp(hostname)) {
        return false
      }
    } else {
      try {
        const addresses = await dns.promises.lookup(hostname, { all: true })
        if (!addresses || addresses.length === 0) {
          return false
        }
        for (const addr of addresses) {
          if (isPrivateIp(addr.address)) {
            return false
          }
        }
      } catch (err) {
        return false
      }
    }
    return true
  } catch (err) {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url !== 'string') {
        next(new Error('Invalid image URL format'))
        return
      }
      
      const isChallenge = url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null
      if (isChallenge) {
        req.app.locals.abused_ssrf_bug = true
      }
      
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!await isSafeUrl(url)) {
            throw new Error('Blocked SSRF attempt')
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
            const isSafe = await isSafeUrl(url)
            if (isSafe) {
              const user = await UserModel.findByPk(loggedInUser.data.id)
              await user?.update({ profileImage: url })
            }
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
