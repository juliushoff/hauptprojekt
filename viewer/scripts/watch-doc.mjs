#!/usr/bin/env node

import { watchTexFiles } from '../lib/document-workspace.mjs'

function readArg(name) {
  const index = process.argv.indexOf(`--${name}`)
  return index === -1 ? '' : process.argv[index + 1] ?? ''
}

const controller = new AbortController()

watchTexFiles({
  scope: readArg('scope') || 'document',
  templateKey: readArg('template'),
  customerSlug: readArg('customer'),
  fileName: readArg('file'),
  signal: controller.signal,
  onBuild(event) {
    console.log(JSON.stringify(event))
  },
})

process.on('SIGINT', () => {
  controller.abort()
  process.exit(0)
})

process.on('SIGTERM', () => {
  controller.abort()
  process.exit(0)
})

console.log('Watching TeX files. Press Ctrl+C to stop.')
