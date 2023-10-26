import type ArtalkPlugin from '~/types/plugin'
import * as Utils from '@/lib/utils'

/** 评论时间自动更新 */
export const ListTimeTicking: ArtalkPlugin = (ctx) => {
  let timer: number|null = null

  ctx.on('inited', () => {
    timer = window.setInterval(() => {
      const list = ctx.get('list')
      if (!list) return

      list.$el.querySelectorAll<HTMLElement>('[data-atk-comment-date]').forEach(el => {
        const date = el.getAttribute('data-atk-comment-date')
        el.innerText = Utils.timeAgo(new Date(Number(date)), ctx)
      })
    }, 30 * 1000) // 30s 更新一次
  })

  ctx.on('destroy', () => {
    timer && window.clearInterval(timer)
  })
}