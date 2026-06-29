import {
  getPdfStream,
  getTemplatePdfStream,
} from '../../../lib/document-workspace.mjs'
import { Readable } from 'stream'

export const dynamic = 'force-dynamic'

export async function GET(request) {
  const params = request.nextUrl.searchParams

  try {
    const { stream, metadata } = params.get('scope') === 'template'
      ? await getTemplatePdfStream(params.get('template'))
      : await getPdfStream(
        params.get('template'),
        params.get('customer'),
        params.get('file')
      )

    return new Response(Readable.toWeb(stream), {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Length': String(metadata.size),
        'Last-Modified': new Date(metadata.updatedAt).toUTCString(),
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    })
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 500
    return new Response(error instanceof Error ? error.message : 'PDF not found.', {
      status,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    })
  }
}
