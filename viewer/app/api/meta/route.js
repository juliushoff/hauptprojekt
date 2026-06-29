import {
  getDocumentMetadata,
  getTemplateMetadata,
} from '../../../lib/document-workspace.mjs'

export const dynamic = 'force-dynamic'

export async function GET(request) {
  const params = request.nextUrl.searchParams

  try {
    const document = params.get('scope') === 'template'
      ? await getTemplateMetadata(params.get('template'))
      : await getDocumentMetadata(
        params.get('template'),
        params.get('customer'),
        params.get('file')
      )

    return Response.json(
      {
        exists: Boolean(document.pdf),
        version: document.pdf?.version ?? 0,
        updatedAt: document.pdf?.updatedAt ?? '',
        size: document.pdf?.size ?? 0,
        document,
      },
      {
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      }
    )
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 500
    return Response.json(
      {
        exists: false,
        version: 0,
        error: error instanceof Error ? error.message : 'Document not found.',
      },
      {
        status,
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      }
    )
  }
}
