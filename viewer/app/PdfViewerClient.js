'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import PdfRuntime from './PdfViewerRuntime'

const STORAGE_KEY = 'documents-viewer:page'
const DEFAULT_TEMPLATE_KEY = 'springer-template'
const DEFAULT_TITLE = 'Hauptprojekt Viewer'
const RENDER_SCALE = 1.45
const TEMPLATE_KEY_ALIASES = new Map([
  ['expose', DEFAULT_TEMPLATE_KEY],
])

function clampPage(page, numPages) {
  if (!Number.isFinite(page)) return 1
  if (numPages <= 0) return Math.max(1, Math.floor(page))
  return Math.min(numPages, Math.max(1, Math.floor(page)))
}

function formatTime(value) {
  if (!value) return 'unknown'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'unknown' : date.toLocaleTimeString()
}

function readInitialPage() {
  if (typeof window === 'undefined') return null

  const params = new URLSearchParams(window.location.search)
  const fromQuery = Number(params.get('page'))
  if (Number.isFinite(fromQuery) && fromQuery > 0) return Math.floor(fromQuery)

  const fromStorage = Number(window.localStorage.getItem(STORAGE_KEY))
  if (Number.isFinite(fromStorage) && fromStorage > 0) return Math.floor(fromStorage)

  return 1
}

function readInitialSelection() {
  if (typeof window === 'undefined') {
    return { scope: 'template', templateKey: DEFAULT_TEMPLATE_KEY, customerSlug: '', fileName: '' }
  }

  const params = new URLSearchParams(window.location.search)
  const hasDocumentParams = params.has('customer') || params.has('file')
  const templateKey = TEMPLATE_KEY_ALIASES.get(params.get('template')) ?? params.get('template') ?? DEFAULT_TEMPLATE_KEY
  return {
    scope: params.get('scope') === 'document' || hasDocumentParams ? 'document' : 'template',
    templateKey,
    customerSlug: params.get('customer') || '',
    fileName: params.get('file') || '',
  }
}

function documentKey(document) {
  return `${document.templateKey}/${document.customerSlug}/${document.fileName}`
}

function pdfUrl(source) {
  if (!source) return ''
  const params = new URLSearchParams({
    scope: source.scope,
    template: source.templateKey,
  })
  if (source.scope === 'document') {
    if (source.customerSlug) params.set('customer', source.customerSlug)
    if (source.fileName) params.set('file', source.fileName)
  }
  if (source.pdf?.version) params.set('v', String(source.pdf.version))
  return `/api/pdf?${params.toString()}`
}

function pdfDownloadName(source) {
  if (!source) return ''
  if (source.scope === 'document' && source.fileName) {
    return source.fileName.replace(/\.tex$/i, '.pdf')
  }
  if (source.scope === 'template' && source.templateKey) {
    return `${source.templateKey}.pdf`
  }
  return 'document.pdf'
}

async function readJson(response) {
  const body = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(body.error || `Request failed with ${response.status}.`)
  }
  return body
}

export default function PdfViewerClient() {
  const [isLoading, setIsLoading] = useState(false)
  const [page, setPage] = useState(null)
  const [pageInput, setPageInput] = useState('1')
  const [numPages, setNumPages] = useState(0)
  const [status, setStatus] = useState('Opening Springer template source.')
  const [lastUpdatedAt, setLastUpdatedAt] = useState('')
  const [scrollToTopRequest, setScrollToTopRequest] = useState(0)
  const [templates, setTemplates] = useState([])
  const [documents, setDocuments] = useState([])
  const [selectedTemplateKey, setSelectedTemplateKey] = useState('')
  const [selectedCustomerSlug, setSelectedCustomerSlug] = useState('')
  const [selectedFileName, setSelectedFileName] = useState('')
  const [watchTemplate, setWatchTemplate] = useState(false)
  const [customerInput, setCustomerInput] = useState('')
  const [workspaceError, setWorkspaceError] = useState('')
  const [buildError, setBuildError] = useState('')
  const [isCreating, setIsCreating] = useState(false)
  const pageRef = useRef(page)
  const numPagesRef = useRef(numPages)

  const selectedDocument = useMemo(() => {
    return documents.find(document => (
      document.templateKey === selectedTemplateKey &&
      document.customerSlug === selectedCustomerSlug &&
      document.fileName === selectedFileName
    )) ?? null
  }, [documents, selectedCustomerSlug, selectedFileName, selectedTemplateKey])

  const selectedTemplate = useMemo(() => {
    return templates.find(template => template.key === selectedTemplateKey) ?? null
  }, [selectedTemplateKey, templates])

  const activeSource = useMemo(() => {
    if (watchTemplate && selectedTemplate) {
      return {
        scope: 'template',
        templateKey: selectedTemplate.key,
        customerSlug: '',
        fileName: '',
        name: selectedTemplate.key,
        sourcePath: selectedTemplate.sourcePath,
        pdf: selectedTemplate.pdf ?? null,
      }
    }

    if (!selectedDocument) return null
    return {
      scope: 'document',
      ...selectedDocument,
    }
  }, [selectedDocument, selectedTemplate, watchTemplate])

  const documentsForTemplate = useMemo(() => {
    return documents.filter(document => document.templateKey === selectedTemplateKey)
  }, [documents, selectedTemplateKey])

  const refreshWorkspace = useCallback(async () => {
    const [templatesResponse, documentsResponse] = await Promise.all([
      fetch('/api/templates', { cache: 'no-store' }),
      fetch('/api/documents', { cache: 'no-store' }),
    ])
    const [templatesPayload, documentsPayload] = await Promise.all([
      readJson(templatesResponse),
      readJson(documentsResponse),
    ])
    setTemplates(templatesPayload.templates ?? [])
    setDocuments(documentsPayload.documents ?? [])
    setWorkspaceError('')
    return {
      templates: templatesPayload.templates ?? [],
      documents: documentsPayload.documents ?? [],
    }
  }, [])

  useEffect(() => {
    const initialPage = readInitialPage()
    const initialSelection = readInitialSelection()
    setPage(initialPage)
    setPageInput(String(initialPage ?? 1))
    setWatchTemplate(initialSelection.scope === 'template')
    setSelectedTemplateKey(initialSelection.templateKey)
    setSelectedCustomerSlug(initialSelection.customerSlug)
    setSelectedFileName(initialSelection.fileName)
  }, [])

  useEffect(() => {
    let cancelled = false

    refreshWorkspace()
      .then(({ templates: nextTemplates, documents: nextDocuments }) => {
        if (cancelled) return
        setSelectedTemplateKey(current => {
          const normalized = TEMPLATE_KEY_ALIASES.get(current) ?? current
          if (normalized && nextTemplates.some(template => template.key === normalized)) return normalized
          return nextTemplates[0]?.key || ''
        })
        setWatchTemplate(current => current || nextDocuments.length === 0)
        setSelectedFileName(current => {
          if (current) return current
          const firstDocument = nextDocuments[0]
          if (firstDocument) {
            setSelectedTemplateKey(firstDocument.templateKey)
            setSelectedCustomerSlug(firstDocument.customerSlug)
            return firstDocument.fileName
          }
          return ''
        })
      })
      .catch(error => {
        if (!cancelled) {
          setWorkspaceError(error instanceof Error ? error.message : 'Could not load workspace.')
        }
      })

    return () => {
      cancelled = true
    }
  }, [refreshWorkspace])

  useEffect(() => {
    if (page === null) return
    pageRef.current = page
    setPageInput(String(page))
    window.localStorage.setItem(STORAGE_KEY, String(page))

    const url = new URL(window.location.href)
    url.searchParams.set('page', String(page))
    if (selectedTemplateKey) {
      url.searchParams.set('template', selectedTemplateKey)
    } else {
      url.searchParams.delete('template')
    }
    if (selectedCustomerSlug && !watchTemplate) {
      url.searchParams.set('customer', selectedCustomerSlug)
    } else {
      url.searchParams.delete('customer')
    }
    if (selectedFileName && !watchTemplate) {
      url.searchParams.set('file', selectedFileName)
    } else {
      url.searchParams.delete('file')
    }
    if (watchTemplate) {
      url.searchParams.set('scope', 'template')
    } else {
      url.searchParams.delete('scope')
    }
    window.history.replaceState({}, '', url)
  }, [page, selectedCustomerSlug, selectedFileName, selectedTemplateKey, watchTemplate])

  useEffect(() => {
    const baseTitle = 'Hauptprojekt Viewer'
    if (!activeSource?.name) {
      document.title = baseTitle
      return
    }
    const stripped = activeSource.name.replace(/^\d{4}-\d{2}-\d{2}_/, '')
    document.title = `${stripped} — ${baseTitle}`
  }, [activeSource])

  useEffect(() => {
    numPagesRef.current = numPages
  }, [numPages])

  const navigateBy = useCallback((delta, scrollToTop = false) => {
    const currentPage = pageRef.current
    if (currentPage === null) return

    const nextPage = clampPage(currentPage + delta, numPagesRef.current)
    if (nextPage === currentPage) return

    if (scrollToTop) {
      setScrollToTopRequest(current => current + 1)
    }
    setPage(nextPage)
  }, [])

  useEffect(() => {
    const onKeyDown = (event) => {
      if (!numPagesRef.current) return
      if (event.target instanceof HTMLElement) {
        const tag = event.target.tagName
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      }

      if (event.key === 'ArrowRight' || event.key === 'PageDown') {
        event.preventDefault()
        navigateBy(1, true)
      }
      if (event.key === 'ArrowLeft' || event.key === 'PageUp') {
        event.preventDefault()
        navigateBy(-1)
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [navigateBy])

  async function createFromTemplate(event) {
    event.preventDefault()
    if (!selectedTemplateKey || !customerInput.trim()) return

    setIsCreating(true)
    setWorkspaceError('')
    setBuildError('')

    try {
      const response = await fetch('/api/documents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          templateKey: selectedTemplateKey,
          customerSlug: customerInput.trim(),
        }),
      })
      const document = await readJson(response)
      const workspace = await refreshWorkspace()
      setCustomerInput('')
      setSelectedTemplateKey(document.templateKey)
      setSelectedCustomerSlug(document.customerSlug)
      setSelectedFileName(document.fileName)
      setWatchTemplate(false)
      setPage(1)
      if (!document.build?.ok) {
        setBuildError(document.build?.log || document.build?.message || 'Build failed.')
        setStatus(document.build?.message || 'Build failed.')
      } else {
        setStatus('Document created.')
      }
      if (!workspace.documents.some(item => documentKey(item) === documentKey(document))) {
        setDocuments(current => [document, ...current])
      }
    } catch (error) {
      setWorkspaceError(error instanceof Error ? error.message : 'Could not create document.')
    } finally {
      setIsCreating(false)
    }
  }

  function openDocument(document) {
    setSelectedTemplateKey(document.templateKey)
    setSelectedCustomerSlug(document.customerSlug)
    setSelectedFileName(document.fileName)
    setWatchTemplate(false)
    setBuildError('')
    setLastUpdatedAt(document.pdf?.updatedAt ?? '')
    setNumPages(0)
    setStatus('Opening document...')
    setPage(1)
    setScrollToTopRequest(current => current + 1)
  }

  return (
    <main className="viewer-shell">
      <section className="viewer-panel">
        <div className="viewer-layout">
          <aside className="viewer-sidebar">
            <div className="viewer-title">
              <h1>{activeSource?.name || DEFAULT_TITLE}</h1>
              <p>Local Springer LaTeX source with live PDF updates from file changes.</p>
            </div>

            <form className="viewer-controls-card" onSubmit={createFromTemplate}>
              <div className="viewer-form">
                <label>
                  <span>Template</span>
                  <select
                    value={selectedTemplateKey}
                    onChange={(event) => {
                      setSelectedTemplateKey(event.target.value)
                      setSelectedCustomerSlug('')
                      setSelectedFileName('')
                      setLastUpdatedAt('')
                      setNumPages(0)
                      setPage(1)
                    }}
                  >
                    {templates.map(template => (
                      <option key={template.key} value={template.key}>
                        {template.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Document copy</span>
                  <div className="viewer-slug-field">
                    <input
                      aria-label="Document copy slug"
                      autoComplete="off"
                      spellCheck="false"
                      value={customerInput}
                      onChange={event => setCustomerInput(event.target.value)}
                      placeholder="optional-copy"
                    />
                  </div>
                </label>
                <label className="viewer-checkbox-row">
                  <input
                    type="checkbox"
                    checked={watchTemplate}
                    disabled={!selectedTemplateKey}
                    onChange={(event) => {
                      setWatchTemplate(event.target.checked)
                      setBuildError('')
                      setLastUpdatedAt('')
                      setNumPages(0)
                      setStatus(event.target.checked ? 'Opening template...' : 'Opening document...')
                      setPage(1)
                      setScrollToTopRequest(current => current + 1)
                    }}
                  />
                  <span>Watch source</span>
                </label>
                <button type="submit" disabled={!selectedTemplateKey || !customerInput.trim() || isCreating}>
                  {isCreating ? 'Creating...' : 'Create copy'}
                </button>
              </div>
            </form>

            <div className="viewer-documents">
              <h2>Copies</h2>
              {documentsForTemplate.length ? (
                <select
                  aria-label="Select document"
                  value={selectedFileName && selectedCustomerSlug ? `${selectedCustomerSlug}/${selectedFileName}` : ''}
                  onChange={(event) => {
                    const match = documentsForTemplate.find(
                      document => `${document.customerSlug}/${document.fileName}` === event.target.value
                    )
                    if (match) openDocument(match)
                  }}
                >
                  <option value="" disabled>Select document</option>
                  {documentsForTemplate.map(document => (
                    <option key={documentKey(document)} value={`${document.customerSlug}/${document.fileName}`}>
                      {document.customerSlug} — {document.name}
                    </option>
                  ))}
                </select>
              ) : (
                <p>No document copies yet. The viewer is watching the source file directly.</p>
              )}
            </div>

            <div className="viewer-controls-card">
              <div className="viewer-controls">
                <div className="viewer-control-row">
                  <button onClick={() => navigateBy(-1)} disabled={page === null || page <= 1}>
                    Previous
                  </button>
                  <button
                    onClick={() => navigateBy(1, true)}
                    disabled={!numPages || page === null || page >= numPages}
                  >
                    Next
                  </button>
                </div>

                <div className="viewer-control-row viewer-control-row-compact">
                  <input
                    aria-label="Page number"
                    inputMode="numeric"
                    value={pageInput}
                    onChange={(event) => {
                      const nextValue = event.target.value
                      setPageInput(nextValue)

                      const value = Number(nextValue)
                      if (Number.isFinite(value)) {
                        setPage(clampPage(value, numPages))
                      }
                    }}
                    onBlur={() => {
                      if (page !== null) {
                        setPageInput(String(page))
                      }
                    }}
                  />
                </div>
              </div>
            </div>

            <div className="viewer-meta">
              <div className="viewer-status">
                <span className="live-dot" />
                <span>{status}</span>
              </div>

              {workspaceError ? <p className="viewer-error">{workspaceError}</p> : null}
              {buildError ? <pre className="viewer-build-log">{buildError}</pre> : null}

              <p className="viewer-stateline">
                Page {page ?? '...'} of {numPages || '...'}.
              </p>
              <p className="viewer-stateline">
                Last PDF update at {formatTime(lastUpdatedAt)}.
              </p>
              {activeSource ? (
                <div className="viewer-stateline viewer-pathrow">
                  <span className="viewer-pathline">{activeSource.sourcePath}</span>
                  <a
                    className="viewer-export-button"
                    href={pdfUrl(activeSource)}
                    download={pdfDownloadName(activeSource)}
                    aria-label={`Save as ${pdfDownloadName(activeSource)}`}
                    title={`Save as ${pdfDownloadName(activeSource)}`}
                  >
                    <svg aria-hidden="true" viewBox="0 0 20 20">
                      <path d="M10 3v9.586l3.293-3.293 1.414 1.414L10 15.414l-4.707-4.707 1.414-1.414L10 12.586V3h0Z" />
                      <path d="M3 15h14v2H3z" />
                    </svg>
                  </a>
                  <a
                    className="viewer-export-button"
                    href={pdfUrl(activeSource)}
                    target="_blank"
                    rel="noreferrer"
                    aria-label="Open PDF in a new tab"
                    title="Open PDF in a new tab"
                  >
                    <svg aria-hidden="true" viewBox="0 0 20 20">
                      <path d="M7 4H4.75A1.75 1.75 0 0 0 3 5.75v9.5C3 16.22 3.78 17 4.75 17h9.5c.97 0 1.75-.78 1.75-1.75V13h-1.5v2.25a.25.25 0 0 1-.25.25h-9.5a.25.25 0 0 1-.25-.25v-9.5c0-.14.11-.25.25-.25H7V4Z" />
                      <path d="M10 3v1.5h4.44l-6.22 6.22 1.06 1.06 6.22-6.22V10H17V3h-7Z" />
                    </svg>
                  </a>
                </div>
              ) : null}
            </div>
          </aside>

          <div className="viewer-stage">
            {!activeSource ? (
              <div className="viewer-message">
                <p><strong>No source selected.</strong></p>
                <p>Select the Springer template or enable source watching.</p>
              </div>
            ) : null}

            {isLoading && !numPages ? (
              <div className="viewer-message">
                <p><strong>Loading viewer...</strong></p>
                <p>The PDF will appear after a successful LaTeX build.</p>
              </div>
            ) : null}

            {page !== null && activeSource ? (
              <PdfRuntime
                key={`${activeSource.scope}/${activeSource.templateKey}/${activeSource.customerSlug}/${activeSource.fileName}`}
                scope={activeSource.scope}
                templateKey={activeSource.templateKey}
                customerSlug={activeSource.scope === 'document' ? activeSource.customerSlug : ''}
                fileName={activeSource.scope === 'document' ? activeSource.fileName : ''}
                page={page}
                renderScale={RENDER_SCALE}
                fitMode={activeSource.templateKey === 'slides' ? 'contain' : 'width'}
                scrollToTopRequest={scrollToTopRequest}
                clampPage={clampPage}
                setIsLoading={setIsLoading}
                setPage={setPage}
                setNumPages={setNumPages}
                setStatus={setStatus}
                setLastUpdatedAt={setLastUpdatedAt}
                setBuildError={setBuildError}
              />
            ) : null}
          </div>
        </div>
      </section>
    </main>
  )
}
