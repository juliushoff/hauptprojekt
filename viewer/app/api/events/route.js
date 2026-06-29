import { watchTexFiles } from '../../../lib/document-workspace.mjs'

export const dynamic = 'force-dynamic'

function sse(event, data) {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`
}

export async function GET(request) {
  const params = request.nextUrl.searchParams
  const scope = params.get('scope') === 'template' ? 'template' : 'document'
  const templateKey = params.get('template')
  const customerSlug = params.get('customer')
  const fileName = params.get('file')
  const encoder = new TextEncoder()
  let closeWatcher = null
  let heartbeat = null

  const stream = new ReadableStream({
    start(controller) {
      const send = (event, data) => {
        try {
          controller.enqueue(encoder.encode(sse(event, data)))
        } catch {}
      }

      try {
        closeWatcher = watchTexFiles({
          scope,
          templateKey,
          customerSlug,
          fileName,
          signal: request.signal,
          buildOnStart: true,
          onBuild(event) {
            send(event.type, event)
          },
        })

        send('connected', {
          scope,
          templateKey,
          customerSlug,
          fileName,
          connectedAt: new Date().toISOString(),
        })
      } catch (error) {
        send('build-error', {
          type: 'build-error',
          reason: 'watch-start',
          message: error instanceof Error ? error.message : 'Could not start watcher.',
          log: '',
        })
      }

      heartbeat = setInterval(() => {
        send('ping', { at: new Date().toISOString() })
      }, 30000)
    },
    cancel() {
      if (heartbeat) clearInterval(heartbeat)
      if (closeWatcher) closeWatcher()
    },
  })

  request.signal.addEventListener('abort', () => {
    if (heartbeat) clearInterval(heartbeat)
    if (closeWatcher) closeWatcher()
  }, { once: true })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Connection: 'keep-alive',
    },
  })
}
