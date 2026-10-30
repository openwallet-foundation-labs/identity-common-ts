import type { Plugin } from 'vite'
import { HOME, PAGES, type Page } from './src/site'

// The parts every page shares, put in at build time so the pages are complete HTML without
// waiting for a script. A page marks where each part goes with a comment, e.g.
// <!-- inspector:header -->.

const escapeHtml = (text: string) =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

const PRIVACY = `<div class="privacy" role="note">
  <svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20">
    <rect x="4" y="10" width="16" height="11" rx="2" />
    <path d="M8 10V7a4 4 0 0 1 8 0v3" />
  </svg>
  <p>
    <strong>Everything stays in your browser.</strong> All parsing and checks run on this page, and nothing you paste,
    drop or check is sent to a server. The page only makes a request when you fetch a URL or check a signer against the
    EU List of Trusted Lists, and your browser sends it straight to that URL. A link to a result holds the input after
    the #, which browsers do not send to a server.
  </p>
</div>`

function parts(page: Page | undefined, root: string): Record<string, string> {
  const title = page ? `${page.title} · EUDI Inspector` : HOME.title
  const description = page?.description ?? HOME.description
  const nav = [
    `<a href="${root}"${page ? '' : ' aria-current="page"'}>${HOME.name}</a>`,
    ...PAGES.map(
      (entry) =>
        `<a href="${root}${entry.id}/"${entry.id === page?.id ? ' aria-current="page"' : ''}>${escapeHtml(entry.name)}</a>`
    ),
  ].join('\n    ')

  return {
    head: `<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="description" content="${escapeHtml(description)}" />
<link rel="icon" href="data:," />
<title>${escapeHtml(title)}</title>`,

    header: `<header class="site-header">
  ${page ? `<p class="brand"><a href="${root}">EUDI Inspector</a></p>` : ''}
  <h1>${escapeHtml(page?.title ?? HOME.title)}</h1>
  <p class="lede">${escapeHtml(description)}${page ? ` <span class="spec">${escapeHtml(page.spec)}</span>` : ''}</p>
  <nav class="site-nav" aria-label="Inspectors">
    ${nav}
  </nav>
  ${PRIVACY}
</header>`,

    fetch: `<form id="url-form" class="url-row">
  <label class="visually-hidden" for="url">URL</label>
  <input type="url" id="url" placeholder="https://… URL of a document" autocomplete="url" required />
  <button type="submit" id="fetch">Fetch</button>
</form>
<div class="divider"><span>or</span></div>`,

    document: `<label class="visually-hidden" for="doc">Document</label>
<textarea id="doc" name="doc" spellcheck="false" placeholder="${escapeHtml(page?.placeholder ?? HOME.placeholder)}"></textarea>`,

    actions: `<div class="actions">
  <button type="submit" class="primary">Inspect</button>
  <button type="button" id="choose-file">Choose file</button>
  <input type="file" id="file" hidden />
  <span class="hint"><kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Enter</kbd></span>
</div>`,

    result: `<div id="error" class="panel error-panel" role="alert" hidden></div>
<section id="result" aria-live="polite" hidden>
  <div id="summary" class="panel summary"></div>
  <div id="extra"></div>
  <div class="panel">
    <h3 id="findings-title">Findings</h3>
    <div id="findings"></div>
  </div>
  <div class="panel">
    <h3>Document</h3>
    <div id="tree"></div>
  </div>
</section>`,

    footer: `<footer class="site-footer">
  Built on
  <a href="https://github.com/openwallet-foundation-labs/identity-common-ts" rel="noopener">identity-common-ts</a>
</footer>`,
  }
}

/** The page of an HTML path, e.g. `/sd-jwt/index.html` or `/sd-jwt/` in development */
function pageOfPath(path: string): { page: Page | undefined; root: string } {
  const directories = path
    .split('?')[0]
    .split('/')
    .filter((segment) => segment && !segment.endsWith('.html'))
  const page = PAGES.find((entry) => entry.id === directories[0])
  return { page, root: directories.length > 0 ? '../'.repeat(directories.length) : './' }
}

export function layout(): Plugin {
  return {
    name: 'inspector-layout',
    transformIndexHtml: {
      order: 'pre',
      handler(html, context) {
        const { page, root } = pageOfPath(context.path)
        const content = parts(page, root)
        return html
          .replace(/<body>/, `<body data-root="${root}">`)
          .replace(/^([ \t]*)<!-- inspector:(\w+) -->$/gm, (_match, indent: string, name: string) => {
            const part = content[name]
            if (part === undefined) throw new Error(`Unknown layout part ${name} in ${context.path}`)
            return part
              .split('\n')
              .map((line) => (line ? indent + line : line))
              .join('\n')
          })
      },
    },
  }
}
