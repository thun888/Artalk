let currentRedirectTemplate: string | undefined

export function setRedirectTemplate(tpl?: string) {
  currentRedirectTemplate = tpl
}

export function getRedirectTemplate(): string | undefined {
  return currentRedirectTemplate
}

/**
 * Apply external link redirect template to a URL.
 * Returns the original URL if no template is set or if the URL is same-origin.
 */
export function applyRedirectTemplate(url: string): string {
  if (!currentRedirectTemplate || !url) return url
  try {
    const linkOrigin = new URL(url).origin
    if (linkOrigin === window.location.origin) return url
  } catch {
    return url
  }
  // console.log('[link-redirect] template:', currentRedirectTemplate, 'url:', url)
  const result = currentRedirectTemplate
    .replace(/\{\{url\}\}/g, encodeURIComponent(url))
    .replace(/\{\{b64url\}\}/g, btoa(url))
  // console.log('[link-redirect] result:', result)
  return result
}
