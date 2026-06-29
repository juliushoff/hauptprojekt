#!/usr/bin/env node

import { createDocument } from '../lib/document-workspace.mjs'

function readArg(name) {
  const index = process.argv.indexOf(`--${name}`)
  return index === -1 ? '' : process.argv[index + 1] ?? ''
}

try {
  const document = await createDocument({
    templateKey: readArg('template'),
    customerSlug: readArg('customer'),
    date: readArg('date') || undefined,
  })

  console.log(JSON.stringify(document, null, 2))
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Could not create document.')
  process.exit(1)
}
