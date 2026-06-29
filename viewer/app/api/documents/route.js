import {
  createDocument,
  listDocuments,
} from '../../../lib/document-workspace.mjs'

export const dynamic = 'force-dynamic'

function errorResponse(error) {
  const status = Number.isInteger(error?.status) ? error.status : 500
  return Response.json(
    { error: error instanceof Error ? error.message : 'Request failed.' },
    {
      status,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    }
  )
}

export async function GET() {
  return Response.json(
    { documents: await listDocuments() },
    {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    }
  )
}

export async function POST(request) {
  try {
    const body = await request.json()
    const document = await createDocument({
      templateKey: body.templateKey,
      customerSlug: body.customerSlug,
      date: body.date,
    })

    return Response.json(document, {
      status: document.build.ok ? 201 : 202,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    })
  } catch (error) {
    return errorResponse(error)
  }
}
