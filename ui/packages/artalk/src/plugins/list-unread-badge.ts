import ArtalkPlugin from '~/types/plugin'

export const ListUnreadBadge: ArtalkPlugin = (ctx) => {
  let $unreadBadge: HTMLElement|null = null

  const showUnreadBadge = (count: number) => {
    if (!$unreadBadge) return

    if (count > 0) {
      $unreadBadge.innerText = `${Number(count || 0)}`
      $unreadBadge.style.display = 'block'
    } else {
      $unreadBadge.style.display = 'none'
    }
  }

  ctx.on('conf-loaded', () => {
    const list = ctx.get('list')
    if (!list) return

    $unreadBadge = list.$el.querySelector<HTMLElement>('.atk-unread-badge')
  })

  ctx.on('unread-updated', (unreadList) => {
    showUnreadBadge(unreadList.length || 0)
  })
}