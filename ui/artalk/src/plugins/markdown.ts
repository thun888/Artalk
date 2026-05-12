import type { ArtalkPlugin } from '@/types'
import * as marked from '@/lib/marked'
import { setRedirectTemplate } from '@/lib/link-redirect'

export const Markdown: ArtalkPlugin = (ctx) => {
  const initMarkedWithCtx = (conf) => {
    marked.initMarked({
      markedOptions: conf.markedOptions,
      imgLazyLoad: conf.imgLazyLoad,
    })
  }

  ctx.watchConf(['imgLazyLoad', 'markedOptions'], (conf) => {
    initMarkedWithCtx(conf)
  })

  ctx.on('list-load', () => {
    const conf = ctx.getConf()
    setRedirectTemplate(ctx.getData().getSiteExternalLinkRedirectTemplate() || undefined)
    initMarkedWithCtx(conf)
  })

  ctx.watchConf(['markedReplacers'], (conf) => {
    conf.markedReplacers && marked.setReplacers(conf.markedReplacers)
  })
}
