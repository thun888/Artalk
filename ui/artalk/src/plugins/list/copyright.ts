import type { ArtalkPlugin } from '@/types'
import { version as ARTALK_VERSION } from '~/package.json'

export const Copyright: ArtalkPlugin = (ctx) => {
  const list = ctx.inject('list')

  ctx.on('mounted', () => {
    const $copyright = list.getEl().querySelector<HTMLElement>('.atk-copyright')
    if (!$copyright) return

    $copyright.innerHTML =
      `Powered By <a href="https://artalk.js.org" ` +
      `target="_blank" title="Artalk v${ARTALK_VERSION}">Artalk</a>` +
      `<br>` +
      `Customized By <a href="https://www.hzchu.top" ` +
      `target="_blank" title="Catch you!">Thun888</a>`
  })
}
