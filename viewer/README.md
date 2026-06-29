# Hauptprojekt Viewer

Small Next.js app for previewing local documents created from the Springer LaTeX template.

The built-in source is:

- `../springerTemplate/sn-article.tex`

The viewer opens:

- `../springerTemplate/sn-article.pdf`

When `.tex`, `.bib`, `.bst`, `.cls`, or `.sty` files inside `../springerTemplate` change,
the server rebuilds `sn-article.tex` with the Springer PDFLaTeX workflow and
pushes a PDF-ready event to the browser.

## Run

From this directory:

```bash
bun run dev
```

The app starts on:

- `http://localhost:8080`

## CLI

Watch and rebuild the Springer template source from the command line:

```bash
bun run watch-doc -- --scope template --template springer-template
```

The legacy copy-from-template flow is still available for local experiments:

```bash
bun run create-doc -- --template springer-template --customer my-copy
```

## Notes

- The browser uses Server-Sent Events for rebuild notifications and fetches the
  PDF only after a successful rebuild.
- The LaTeX build uses `latexmk -pdf` when available and falls back to
  `pdflatex`.
