import { listTemplates } from '../../../lib/document-workspace.mjs'

export const dynamic = 'force-dynamic'

export async function GET() {
  return Response.json(
    { templates: await listTemplates() },
    {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    }
  )
}
