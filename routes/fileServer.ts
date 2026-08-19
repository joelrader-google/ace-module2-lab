/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    const fileLower = file ? file.toLowerCase() : ''
    if (fileLower.includes('/') || fileLower.includes('\\') || fileLower.includes('..') || fileLower.includes('%2f') || fileLower.includes('%5c')) {
      res.status(403)
      next(new Error('File names cannot contain directory traversal or path separators!'))
    } else {
      verify(file, res, next)
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (!file) {
      res.status(403)
      return next(new Error('File parameter is required!'))
    }

    const cleanFile = security.cutOffPoisonNullByte(file)
    const isAllowedFileType = endsWithAllowlistedFileType(cleanFile) || cleanFile === 'incident-support.kdbx'

    const allowedChallengeFiles = [
      'eastere.gg',
      'package.json.bak',
      'coupons_2013.md.bak',
      'suspicious_errors.yml',
      'encrypt.pyc'
    ]
    const isAllowedChallengeFile = allowedChallengeFiles.includes(cleanFile.toLowerCase())

    const hasNullByte = cleanFile !== file
    const isSafe = isAllowedFileType || (hasNullByte && isAllowedChallengeFile)

    if (isSafe) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return cleanFile.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(cleanFile)

      res.sendFile(path.resolve('ftp/', cleanFile))
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
