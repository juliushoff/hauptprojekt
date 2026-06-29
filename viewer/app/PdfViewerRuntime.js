'use client'

import { useEffect, useRef } from 'react'
import { AnnotationLayer, getDocument, TextLayer } from 'pdfjs-dist/webpack.mjs'

function documentParams(scope, templateKey, customerSlug, fileName, version = '') {
  const params = new URLSearchParams({
    scope,
    template: templateKey,
  })

  if (customerSlug) params.set('customer', customerSlug)
  if (fileName) params.set('file', fileName)
  if (version !== '') params.set('v', String(version))
  return params.toString()
}

export default function PdfViewerRuntime({
  scope = 'document',
  templateKey,
  customerSlug,
  fileName,
  page,
  renderScale,
  fitMode = 'width',
  scrollToTopRequest,
  clampPage,
  setIsLoading,
  setPage,
  setNumPages,
  setStatus,
  setLastUpdatedAt,
  setBuildError,
}) {
  const canvasRef = useRef(null)
  const textLayerRef = useRef(null)
  const annotationLayerRef = useRef(null)
  const pageContainerRef = useRef(null)
  const scrollContainerRef = useRef(null)
  const pdfRef = useRef(null)
  const renderTaskRef = useRef(null)
  const textLayerTaskRef = useRef(null)
  const pendingRenderRef = useRef(null)
  const pageRef = useRef(page)
  const renderedPageRef = useRef(0)
  const handledScrollToTopRequestRef = useRef(scrollToTopRequest)
  const isReadyRef = useRef(false)
  const isRenderingRef = useRef(false)
  const watcherLabel = scope === 'template' ? 'template' : 'document'
  const linkServiceRef = useRef({
    externalLinkTarget: 2,
    externalLinkRel: 'noopener noreferrer nofollow',
    externalLinkEnabled: true,
    isInPresentationMode: false,
    getDestinationHash(destination) {
      return typeof destination === 'string' ? `#${destination}` : ''
    },
    getAnchorUrl(hash) {
      return hash || ''
    },
    goToDestination() {},
    executeNamedAction() {},
    executeSetOCGState() {},
  })

  // In 'contain' mode (slides) the page is scaled so the WHOLE page fits the
  // visible stage area, preserving aspect ratio (no distortion, no scroll).
  // In 'width' mode (A4 docs) the fixed renderScale is used as before.
  const SLIDE_PADDING = 24
  function computeRenderScale(pdfPage) {
    if (fitMode !== 'contain') return renderScale
    const container = scrollContainerRef.current
    if (!container) return renderScale
    const base = pdfPage.getViewport({ scale: 1 })
    const availWidth = container.clientWidth - SLIDE_PADDING * 2
    const availHeight = container.clientHeight - SLIDE_PADDING * 2
    if (availWidth <= 0 || availHeight <= 0) return renderScale
    const fit = Math.min(availWidth / base.width, availHeight / base.height)
    return fit > 0 ? fit : renderScale
  }

  async function fetchMeta() {
    const response = await fetch(`/api/meta?${documentParams(scope, templateKey, customerSlug, fileName)}`, {
      cache: 'no-store',
    })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      throw new Error(body.error || 'Document PDF not found.')
    }
    return response.json()
  }

  function scrollRenderedPageToTop() {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTo({
        top: 0,
        left: scrollContainerRef.current.scrollLeft,
        behavior: 'auto',
      })
    }

    window.scrollTo({
      top: 0,
      left: window.scrollX,
      behavior: 'auto',
    })
  }

  async function renderPage(pdfDoc, targetPage, reason = `Watching ${watcherLabel} sources...`) {
    pendingRenderRef.current = { pdfDoc, targetPage, reason }

    if (isRenderingRef.current) {
      if (renderTaskRef.current) {
        try {
          renderTaskRef.current.cancel()
        } catch {}
      }
      if (textLayerTaskRef.current) {
        try {
          textLayerTaskRef.current.cancel()
        } catch {}
      }
      return
    }

    while (pendingRenderRef.current) {
      const nextRender = pendingRenderRef.current
      pendingRenderRef.current = null

      if (!canvasRef.current || !textLayerRef.current || !annotationLayerRef.current || !pageContainerRef.current) return
      isRenderingRef.current = true

      try {
        const safePage = clampPage(nextRender.targetPage, nextRender.pdfDoc.numPages)
        const pdfPage = await nextRender.pdfDoc.getPage(safePage)
        const viewport = pdfPage.getViewport({ scale: computeRenderScale(pdfPage) })
        const canvas = canvasRef.current
        const textLayerContainer = textLayerRef.current
        const annotationLayerContainer = annotationLayerRef.current
        const pageContainer = pageContainerRef.current
        const outputScale = Math.min(window.devicePixelRatio || 1, 2)
        const context = canvas.getContext('2d')

        if (!context) {
          throw new Error('Could not create canvas context.')
        }

        textLayerContainer.innerHTML = ''
        annotationLayerContainer.innerHTML = ''
        canvas.width = Math.floor(viewport.width * outputScale)
        canvas.height = Math.floor(viewport.height * outputScale)
        canvas.style.width = `${viewport.width}px`
        canvas.style.height = `${viewport.height}px`
        pageContainer.style.width = `${viewport.width}px`
        pageContainer.style.height = `${viewport.height}px`
        textLayerContainer.style.width = `${viewport.width}px`
        textLayerContainer.style.height = `${viewport.height}px`
        annotationLayerContainer.style.width = `${viewport.width}px`
        annotationLayerContainer.style.height = `${viewport.height}px`
        context.setTransform(1, 0, 0, 1, 0, 0)
        context.clearRect(0, 0, canvas.width, canvas.height)
        context.fillStyle = '#ffffff'
        context.fillRect(0, 0, canvas.width, canvas.height)
        context.setTransform(outputScale, 0, 0, outputScale, 0, 0)

        const canvasTask = pdfPage.render({
          canvasContext: context,
          viewport,
        })
        renderTaskRef.current = canvasTask
        await canvasTask.promise

        const textContent = await pdfPage.getTextContent()
        const textLayerTask = new TextLayer({
          container: textLayerContainer,
          textContentSource: textContent,
          viewport,
        })
        textLayerTaskRef.current = textLayerTask
        await textLayerTask.render()

        const annotations = await pdfPage.getAnnotations({ intent: 'display' })
        if (annotations.length > 0) {
          const annotationLayer = new AnnotationLayer({
            div: annotationLayerContainer,
            accessibilityManager: null,
            annotationCanvasMap: null,
            annotationEditorUIManager: null,
            page: pdfPage,
            viewport: viewport.clone({ dontFlip: true }),
            structTreeLayer: null,
          })
          await annotationLayer.render({
            annotations,
            imageResourcesPath: '',
            renderForms: false,
            linkService: linkServiceRef.current,
            downloadManager: null,
            annotationStorage: pdfDoc.annotationStorage,
            enableScripting: false,
            hasJSActions: false,
            fieldObjects: null,
          })
        }

        renderTaskRef.current = null
        textLayerTaskRef.current = null
        renderedPageRef.current = safePage
        if (safePage !== nextRender.targetPage) {
          setPage(current => (current === safePage ? current : safePage))
        }
        setStatus(nextRender.reason)

        if (scrollToTopRequest !== handledScrollToTopRequestRef.current) {
          handledScrollToTopRequestRef.current = scrollToTopRequest
          scrollRenderedPageToTop()
        }
      } catch (error) {
        renderTaskRef.current = null
        textLayerTaskRef.current = null
        if (error?.name !== 'RenderingCancelledException') {
          throw error
        }
      } finally {
        isRenderingRef.current = false
      }
    }
  }

  async function loadPdf(version, preferredPage, reason) {
    setIsLoading(true)
    setStatus('Rendering PDF...')
    const task = getDocument(`/api/pdf?${documentParams(scope, templateKey, customerSlug, fileName, version)}`)
    const pdfDoc = await task.promise
    pdfRef.current = pdfDoc
    setNumPages(pdfDoc.numPages)
    await renderPage(pdfDoc, preferredPage, reason)
    setIsLoading(false)
  }

  useEffect(() => {
    let cancelled = false
    let events = null

    async function initialize() {
      isReadyRef.current = false
      renderedPageRef.current = 0
      pdfRef.current = null
      setBuildError('')

      try {
        const meta = await fetchMeta()
        if (cancelled) return
        if (meta.exists) {
          setLastUpdatedAt(meta.updatedAt)
          await loadPdf(meta.version, pageRef.current, `Connected to ${watcherLabel} watcher.`)
        } else {
          setNumPages(0)
          setStatus('Waiting for first PDF build...')
        }
        isReadyRef.current = true
      } catch (error) {
        if (cancelled) return
        setStatus(error instanceof Error ? error.message : 'Could not load PDF.')
        setIsLoading(false)
      }

      if (cancelled) return
      events = new EventSource(`/api/events?${documentParams(scope, templateKey, customerSlug, fileName)}`)
      events.addEventListener('connected', () => {
        setStatus(`Connected to ${watcherLabel} watcher.`)
      })
      events.addEventListener('pdf-ready', async event => {
        try {
          const data = JSON.parse(event.data)
          if (cancelled) return
          setBuildError('')
          setLastUpdatedAt(data.updatedAt)
          await loadPdf(data.version, pageRef.current, `PDF updated from ${watcherLabel} watcher.`)
        } catch (error) {
          if (!cancelled) {
            setStatus(error instanceof Error ? error.message : 'Could not refresh PDF.')
          }
        }
      })
      events.addEventListener('build-error', event => {
        try {
          const data = JSON.parse(event.data)
          setBuildError(data.log || data.message || 'Build failed.')
          setStatus(data.message || 'Build failed.')
        } catch {
          setBuildError('Build failed.')
          setStatus('Build failed.')
        }
      })
      events.onerror = () => {
        if (!cancelled) setStatus(`${watcherLabel[0].toUpperCase()}${watcherLabel.slice(1)} watcher disconnected.`)
      }
    }

    initialize()

    return () => {
      cancelled = true
      if (events) events.close()
      if (renderTaskRef.current) {
        try {
          renderTaskRef.current.cancel()
        } catch {}
      }
      if (textLayerTaskRef.current) {
        try {
          textLayerTaskRef.current.cancel()
        } catch {}
      }
    }
  }, [
    clampPage,
    customerSlug,
    fileName,
    renderScale,
    fitMode,
    setBuildError,
    setIsLoading,
    setLastUpdatedAt,
    setNumPages,
    setPage,
    setStatus,
    scope,
    templateKey,
    watcherLabel,
  ])

  useEffect(() => {
    pageRef.current = page
    if (!isReadyRef.current || !pdfRef.current) return
    if (renderedPageRef.current === page) return
    renderPage(pdfRef.current, page)
  }, [page, scrollToTopRequest, setStatus])

  // Re-fit slides when the stage is resized (contain mode only).
  useEffect(() => {
    if (fitMode !== 'contain') return
    const container = scrollContainerRef.current
    if (!container || typeof ResizeObserver === 'undefined') return
    let frame = 0
    const observer = new ResizeObserver(() => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        if (pdfRef.current && isReadyRef.current) {
          renderPage(pdfRef.current, pageRef.current)
        }
      })
    })
    observer.observe(container)
    return () => {
      cancelAnimationFrame(frame)
      observer.disconnect()
    }
  }, [fitMode])

  return (
    <div
      ref={scrollContainerRef}
      className={fitMode === 'contain' ? 'viewer-canvas-wrap is-slide' : 'viewer-canvas-wrap'}
    >
      <div ref={pageContainerRef} className="viewer-page">
        <canvas ref={canvasRef} className="viewer-canvas" />
        <div ref={textLayerRef} className="textLayer viewer-text-layer" />
        <div ref={annotationLayerRef} className="annotationLayer viewer-annotation-layer" />
      </div>
    </div>
  )
}
