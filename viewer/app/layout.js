import './globals.css'
import 'pdfjs-dist/web/pdf_viewer.css'

export const metadata = {
  title: 'Hauptprojekt Viewer',
  description: 'Local Springer LaTeX viewer with live PDF updates.',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
