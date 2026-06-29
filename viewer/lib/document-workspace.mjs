import { constants, createReadStream } from 'fs'
import {
  access,
  copyFile,
  cp,
  mkdir,
  readdir,
  rm,
  stat,
} from 'fs/promises'
import { watch } from 'fs'
import path from 'path'
import { spawn } from 'child_process'
import { fileURLToPath } from 'url'

const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/
const DOCUMENT_FILE_PATTERN = /^\d{4}-\d{2}-\d{2}_[A-Z][A-Za-z0-9]*-[A-Z][A-Za-z0-9]*\.tex$/
const SPRINGER_TEMPLATE_KEY = 'springer-template'
const SPRINGER_TEMPLATE_DIR = 'springerTemplate'
const SPRINGER_TEMPLATE_MAIN_FILE = 'sn-article.tex'
const TEMPLATE_KEY_ALIASES = new Map([
  ['expose', SPRINGER_TEMPLATE_KEY],
])
const LATEX_SOURCE_EXTENSIONS = new Set(['.bib', '.bst', '.cls', '.sty', '.tex'])
const BUILD_OUTPUT_EXTENSIONS = new Set([
  '.aux',
  '.bbl',
  '.bcf',
  '.blg',
  '.fdb_latexmk',
  '.fls',
  '.idx',
  '.ilg',
  '.ind',
  '.lof',
  '.log',
  '.lot',
  '.out',
  '.pdf',
  '.run.xml',
  '.synctex.gz',
  '.toc',
  '.xdv',
])

const moduleDir = path.dirname(fileURLToPath(import.meta.url))

export const workspaceRoot = path.resolve(moduleDir, '..', '..')
export const templatesRoot = path.join(workspaceRoot, 'templates')
export const documentsRoot = path.join(workspaceRoot, 'documents')
export const assetsRoot = path.join(workspaceRoot, 'assets')
export const springerTemplateRoot = path.join(workspaceRoot, SPRINGER_TEMPLATE_DIR)

export function sanitizeSlug(value) {
  return String(value ?? '')
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-')
}

export function pascalCase(slug) {
  return String(slug ?? '')
    .split('-')
    .filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join('')
}

export function formatIsoDate(date = new Date()) {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Berlin',
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  })

  return formatter.format(date)
}

export function createDocumentFilename(templateKey, customerSlug, date = new Date()) {
  templateKey = normalizeTemplateKey(templateKey)
  assertSlug(templateKey, 'template')
  assertSlug(customerSlug, 'copy name')
  const template = pascalCase(templateKey)
  const customer = pascalCase(customerSlug)
  if (!template || !customer) {
    throw Object.assign(new Error('Slug is required.'), { status: 400 })
  }
  return `${formatIsoDate(date)}_${template}-${customer}.tex`
}

function assertSlug(name, label) {
  if (!SLUG_PATTERN.test(name)) {
    throw Object.assign(new Error(`Invalid ${label}.`), { status: 400 })
  }
}

function assertDocumentFileName(fileName) {
  if (!DOCUMENT_FILE_PATTERN.test(fileName)) {
    throw Object.assign(new Error('Invalid document file name.'), { status: 400 })
  }
}

export function normalizeTemplateKey(templateKey) {
  return TEMPLATE_KEY_ALIASES.get(templateKey) ?? templateKey
}

async function ensureExists(filePath, statusCode, message) {
  try {
    await access(filePath, constants.F_OK)
  } catch {
    throw Object.assign(new Error(message), { status: statusCode })
  }
}

export function getTemplatePath(templateKey) {
  templateKey = normalizeTemplateKey(templateKey)
  assertSlug(templateKey, 'template')
  if (templateKey === SPRINGER_TEMPLATE_KEY) return springerTemplateRoot
  return path.join(templatesRoot, templateKey)
}

export function getTemplateMainPath(templateKey) {
  return path.join(getTemplatePath(templateKey), getTemplateSourceFileName(templateKey))
}

export function getTemplatePdfPath(templateKey) {
  return path.join(getTemplatePath(templateKey), getTemplatePdfFileName(templateKey))
}

function getTemplateSourceFileName(templateKey) {
  templateKey = normalizeTemplateKey(templateKey)
  return templateKey === SPRINGER_TEMPLATE_KEY ? SPRINGER_TEMPLATE_MAIN_FILE : 'main.tex'
}

function getTemplatePdfFileName(templateKey) {
  return getTemplateSourceFileName(templateKey).replace(/\.tex$/, '.pdf')
}

export function getDocumentDir(templateKey, customerSlug) {
  templateKey = normalizeTemplateKey(templateKey)
  assertSlug(templateKey, 'template')
  assertSlug(customerSlug, 'copy name')
  return path.join(documentsRoot, templateKey, customerSlug)
}

export function getDocumentTexPath(templateKey, customerSlug, fileName) {
  assertDocumentFileName(fileName)
  return path.join(getDocumentDir(templateKey, customerSlug), fileName)
}

export function getDocumentPdfPath(templateKey, customerSlug, fileName) {
  assertDocumentFileName(fileName)
  return path.join(getDocumentDir(templateKey, customerSlug), fileName.replace(/\.tex$/, '.pdf'))
}

export async function listTemplates() {
  const templates = []

  try {
    const mainStat = await stat(getTemplateMainPath(SPRINGER_TEMPLATE_KEY))
    let pdf = null
    try {
      pdf = pdfMetadata(await stat(getTemplatePdfPath(SPRINGER_TEMPLATE_KEY)))
    } catch {}

    templates.push({
      key: SPRINGER_TEMPLATE_KEY,
      label: 'Springer template',
      sourcePath: getTemplateMainPath(SPRINGER_TEMPLATE_KEY),
      updatedAt: mainStat.mtime.toISOString(),
      pdf,
    })
  } catch {}

  try {
    const entries = await readdir(templatesRoot, { withFileTypes: true })

    for (const entry of entries) {
      if (!entry.isDirectory() || !SLUG_PATTERN.test(entry.name)) continue
      if (entry.name === SPRINGER_TEMPLATE_KEY) continue
      const mainPath = path.join(templatesRoot, entry.name, 'main.tex')
      try {
        const fileStat = await stat(mainPath)
        let pdf = null
        try {
          pdf = pdfMetadata(await stat(getTemplatePdfPath(entry.name)))
        } catch {}

        templates.push({
          key: entry.name,
          label: entry.name,
          sourcePath: mainPath,
          updatedAt: fileStat.mtime.toISOString(),
          pdf,
        })
      } catch {}
    }
  } catch {}

  return templates.sort((left, right) => left.key.localeCompare(right.key))
}

export async function listDocuments() {
  try {
    const templateEntries = await readdir(documentsRoot, { withFileTypes: true })
    const documents = []

    for (const templateEntry of templateEntries) {
      if (!templateEntry.isDirectory() || !SLUG_PATTERN.test(templateEntry.name)) continue
      const templateKey = templateEntry.name
      const templateDir = path.join(documentsRoot, templateKey)
      const customerEntries = await readdir(templateDir, { withFileTypes: true })

      for (const customerEntry of customerEntries) {
        if (!customerEntry.isDirectory() || !SLUG_PATTERN.test(customerEntry.name)) continue
        const customerSlug = customerEntry.name
        const customerDir = path.join(templateDir, customerSlug)
        const fileEntries = await readdir(customerDir, { withFileTypes: true })

        for (const fileEntry of fileEntries) {
          if (!fileEntry.isFile() || !DOCUMENT_FILE_PATTERN.test(fileEntry.name)) continue
          const fileName = fileEntry.name
          const sourcePath = path.join(customerDir, fileName)
          const pdfPath = path.join(customerDir, fileName.replace(/\.tex$/, '.pdf'))

          try {
            const sourceStat = await stat(sourcePath)
            let pdf = null
            try {
              pdf = pdfMetadata(await stat(pdfPath))
            } catch {}

            documents.push({
              templateKey,
              customerSlug,
              fileName,
              name: fileName.replace(/\.tex$/, ''),
              sourcePath,
              updatedAt: sourceStat.mtime.toISOString(),
              pdf,
            })
          } catch {}
        }
      }
    }

    return documents.sort((left, right) => {
      const byTemplate = left.templateKey.localeCompare(right.templateKey)
      if (byTemplate) return byTemplate
      const byCustomer = left.customerSlug.localeCompare(right.customerSlug)
      if (byCustomer) return byCustomer
      return right.fileName.localeCompare(left.fileName)
    })
  } catch {
    return []
  }
}

export async function createDocument({ templateKey, customerSlug, date }) {
  templateKey = normalizeTemplateKey(templateKey)
  assertSlug(templateKey, 'template')
  const copySlug = sanitizeSlug(customerSlug)
  assertSlug(copySlug, 'copy name')
  await ensureExists(getTemplateMainPath(templateKey), 404, 'Template not found.')

  const fileName = createDocumentFilename(templateKey, copySlug, date ? new Date(date) : new Date())
  const customerDir = getDocumentDir(templateKey, copySlug)
  const texPath = path.join(customerDir, fileName)

  await mkdir(customerDir, { recursive: true })

  let exists = false
  try {
    await access(texPath, constants.F_OK)
    exists = true
  } catch {}
  if (exists) {
    throw Object.assign(new Error('Document already exists.'), { status: 409 })
  }

  await copyFile(getTemplateMainPath(templateKey), texPath)
  await copyTemplateSupportFiles(templateKey, customerDir)

  const build = await compileDocument(templateKey, copySlug, fileName)
  return buildDocumentResponse(templateKey, copySlug, fileName, build)
}

async function copyTemplateSupportFiles(templateKey, customerDir) {
  const templatePath = getTemplatePath(templateKey)
  const entries = await readdir(templatePath, { withFileTypes: true })
  const sourceFileName = getTemplateSourceFileName(templateKey)
  const sourceBaseName = path.parse(sourceFileName).name

  await Promise.all(entries.map(async entry => {
    if (entry.name === sourceFileName) return
    if (isBuildOutputForSource(entry.name, sourceBaseName)) return

    const sourcePath = path.join(templatePath, entry.name)
    const destinationPath = path.join(customerDir, entry.name)

    if (entry.isDirectory()) {
      await cp(sourcePath, destinationPath, { recursive: true })
      return
    }

    if (entry.isFile()) {
      await copyFile(sourcePath, destinationPath)
    }
  }))
}

function isBuildOutputForSource(fileName, sourceBaseName) {
  const parsed = path.parse(fileName)
  return parsed.name === sourceBaseName && isBuildOutput(fileName)
}

export async function getPdfStream(templateKey, customerSlug, fileName) {
  const pdfPath = getDocumentPdfPath(templateKey, customerSlug, fileName)
  await ensureExists(pdfPath, 404, 'PDF not found.')
  const fileStat = await stat(pdfPath)

  return {
    stream: createReadStream(pdfPath),
    metadata: pdfMetadata(fileStat),
  }
}

export async function getTemplatePdfStream(templateKey) {
  const pdfPath = getTemplatePdfPath(templateKey)
  await ensureExists(pdfPath, 404, 'PDF not found.')
  const fileStat = await stat(pdfPath)

  return {
    stream: createReadStream(pdfPath),
    metadata: pdfMetadata(fileStat),
  }
}

export async function getDocumentMetadata(templateKey, customerSlug, fileName) {
  const sourcePath = getDocumentTexPath(templateKey, customerSlug, fileName)
  await ensureExists(sourcePath, 404, 'Document not found.')

  let pdf = null
  try {
    pdf = pdfMetadata(await stat(getDocumentPdfPath(templateKey, customerSlug, fileName)))
  } catch {}

  return {
    templateKey,
    customerSlug,
    fileName,
    name: fileName.replace(/\.tex$/, ''),
    sourcePath,
    pdf,
  }
}

export async function getTemplateMetadata(templateKey) {
  const sourcePath = getTemplateMainPath(templateKey)
  await ensureExists(sourcePath, 404, 'Template not found.')

  let pdf = null
  try {
    pdf = pdfMetadata(await stat(getTemplatePdfPath(templateKey)))
  } catch {}

  return {
    scope: 'template',
    templateKey,
    name: templateKey,
    sourcePath,
    pdf,
  }
}

export async function compileDocument(templateKey, customerSlug, fileName) {
  const customerDir = getDocumentDir(templateKey, customerSlug)
  const texPath = getDocumentTexPath(templateKey, customerSlug, fileName)
  await ensureExists(texPath, 404, 'Document not found.')

  return compileTexFile(customerDir, fileName)
}

export async function compileTemplate(templateKey) {
  const templatePath = getTemplatePath(templateKey)
  await ensureExists(getTemplateMainPath(templateKey), 404, 'Template not found.')

  return compileTexFile(templatePath, getTemplateSourceFileName(templateKey))
}

async function compileTexFile(cwd, fileName) {
  await rm(path.join(cwd, fileName.replace(/\.tex$/, '.pdf')), { force: true })

  const latexmk = await runCommand('latexmk', [
    '-pdf',
    '-interaction=nonstopmode',
    '-halt-on-error',
    fileName,
  ], cwd)

  if (latexmk.ok) {
    return buildSuccess(cwd, fileName, latexmk)
  }

  if (latexmk.missingCommand || looksLikeToolingFailure(latexmk.output)) {
    const pdflatex = await runPdflatexTwice(cwd, fileName)

    if (pdflatex.ok) {
      return buildSuccess(cwd, fileName, pdflatex)
    }

    return buildFailure(pdflatex)
  }

  return buildFailure(latexmk)
}

async function runPdflatexTwice(cwd, fileName) {
  const first = await runCommand('pdflatex', [
    '-interaction=nonstopmode',
    '-halt-on-error',
    fileName,
  ], cwd)

  if (!first.ok) return first

  return runCommand('pdflatex', [
    '-interaction=nonstopmode',
    '-halt-on-error',
    fileName,
  ], cwd)
}

function looksLikeToolingFailure(output) {
  if (!output) return false
  return /script engine|Can't locate .*\.pm|perl(?:\.exe)? (?:is not|was not|not found)|command not found/i.test(output)
}

export function watchTexFiles({
  scope = 'document',
  templateKey,
  customerSlug,
  fileName,
  signal,
  onBuild,
  buildOnStart = false,
}) {
  const watchTemplate = scope === 'template'
  const sourcePath = watchTemplate
    ? getTemplatePath(templateKey)
    : getDocumentDir(templateKey, customerSlug)
  const mainPath = watchTemplate
    ? getTemplateMainPath(templateKey)
    : getDocumentTexPath(templateKey, customerSlug, fileName)
  const pdfPath = watchTemplate
    ? getTemplatePdfPath(templateKey)
    : getDocumentPdfPath(templateKey, customerSlug, fileName)
  let watcher = null
  let debounceTimer = null
  let building = false
  let pending = false
  let previousVersion = 0

  async function rebuild(reason) {
    if (building) {
      pending = true
      return
    }

    building = true
    try {
      const result = watchTemplate
        ? await compileTemplate(templateKey)
        : await compileDocument(templateKey, customerSlug, fileName)
      if (result.ok) {
        const version = result.pdf?.version ?? 0
        if (version !== previousVersion) {
          previousVersion = version
          onBuild({ type: 'pdf-ready', reason, ...result.pdf })
        }
      } else {
        onBuild({
          type: 'build-error',
          reason,
          message: result.message,
          log: result.log,
        })
      }
    } catch (error) {
      onBuild({
        type: 'build-error',
        reason,
        message: error instanceof Error ? error.message : 'Build failed.',
        log: '',
      })
    } finally {
      building = false
      if (pending) {
        pending = false
        schedule('queued')
      }
    }
  }

  function schedule(reason) {
    clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => {
      rebuild(reason)
    }, 250)
  }

  function close() {
    clearTimeout(debounceTimer)
    if (watcher) watcher.close()
  }

  ensureExists(mainPath, 404, watchTemplate ? 'Template not found.' : 'Document not found.')
    .then(async () => {
      try {
        previousVersion = (await stat(pdfPath)).mtimeMs
      } catch {}

      watcher = watch(sourcePath, { recursive: true }, (_event, changed) => {
        if (!isTexSourceChange(changed)) return
        schedule(String(changed))
      })

      if (buildOnStart) schedule('watch-start')

      if (signal?.aborted) close()
      signal?.addEventListener('abort', close, { once: true })
    })
    .catch(error => {
      onBuild({
        type: 'build-error',
        reason: 'watch-start',
        message: error instanceof Error ? error.message : 'Could not start watcher.',
        log: '',
      })
    })

  return close
}

export async function cleanBuildArtifacts(templateKey, customerSlug) {
  const customerDir = getDocumentDir(templateKey, customerSlug)
  const entries = await readdir(customerDir)
  await Promise.all(entries.map(async entry => {
    if (!isBuildOutput(entry)) return
    await rm(path.join(customerDir, entry), { force: true })
  }))
}

function pdfMetadata(fileStat) {
  return {
    exists: true,
    version: fileStat.mtimeMs,
    updatedAt: fileStat.mtime.toISOString(),
    size: fileStat.size,
  }
}

function buildDocumentResponse(templateKey, customerSlug, fileName, build) {
  return {
    templateKey,
    customerSlug,
    fileName,
    name: fileName.replace(/\.tex$/, ''),
    sourcePath: getDocumentTexPath(templateKey, customerSlug, fileName),
    pdf: build.pdf ?? null,
    build,
  }
}

async function buildSuccess(cwd, fileName, commandResult) {
  const pdfPath = path.join(cwd, fileName.replace(/\.tex$/, '.pdf'))
  const fileStat = await stat(pdfPath)
  return {
    ok: true,
    command: commandResult.command,
    log: commandResult.output,
    pdf: pdfMetadata(fileStat),
  }
}

function buildFailure(commandResult) {
  return {
    ok: false,
    command: commandResult.command,
    message: commandResult.message || 'LaTeX build failed.',
    log: tail(commandResult.output),
  }
}

function buildTexEnv() {
  const sep = path.delimiter
  const toKpsePath = value => String(value).replace(/\\/g, '/')
  const assetsEntry = `${toKpsePath(assetsRoot)}//`
  const fontsEntry = `${toKpsePath(path.join(assetsRoot, 'fonts'))}//`
  return {
    TEXINPUTS: `${assetsEntry}${sep}${process.env.TEXINPUTS ?? ''}`,
    TTFONTS: `${fontsEntry}${sep}${process.env.TTFONTS ?? ''}`,
    OPENTYPEFONTS: `${fontsEntry}${sep}${process.env.OPENTYPEFONTS ?? ''}`,
    OSFONTDIR: `${fontsEntry}${sep}${process.env.OSFONTDIR ?? ''}`,
  }
}

async function runCommand(command, args, cwd) {
  return new Promise(resolve => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...buildTexEnv() },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let output = ''

    child.stdout.on('data', chunk => {
      output += chunk.toString()
    })
    child.stderr.on('data', chunk => {
      output += chunk.toString()
    })
    child.on('error', error => {
      resolve({
        ok: false,
        command,
        output,
        missingCommand: error.code === 'ENOENT',
        message: error.code === 'ENOENT'
          ? `${command} is not installed or not on PATH.`
          : error.message,
      })
    })
    child.on('close', code => {
      resolve({
        ok: code === 0,
        command,
        output,
        message: code === 0 ? '' : `${command} exited with code ${code}.`,
      })
    })
  })
}

function isTexSourceChange(fileName) {
  if (!fileName) return false
  const normalized = String(fileName).replace(/\\/g, '/')
  const baseName = path.basename(normalized)
  if (baseName.startsWith('.')) return false
  if (isBuildOutput(baseName)) return false
  return LATEX_SOURCE_EXTENSIONS.has(path.extname(normalized).toLowerCase())
}

function isBuildOutput(fileName) {
  const normalized = String(fileName).toLowerCase()
  if (normalized.endsWith('.synctex.gz')) return true
  if (normalized.endsWith('.run.xml')) return true
  return BUILD_OUTPUT_EXTENSIONS.has(path.extname(normalized))
}

function tail(value, maxLength = 5000) {
  if (!value) return ''
  return value.length <= maxLength ? value : value.slice(value.length - maxLength)
}
