import * as Utils from '../../lib/utils'
import type Render from '../render'
import $t from '@/i18n'

/**
 * 评论标签行 - 显示在操作按钮下方
 */
export default function renderTags(r: Render) {
  r.$tags.innerHTML = ''

  // 管理员点赞标签
  if (r.data.admin_up && r.data.admin_badge_name) {
    const $tag = Utils.createElement(`<span class="atk-tag"></span>`)
    $tag.innerText = `${r.data.admin_badge_name}${$t('adminVoteUp')}`
    r.$tags.append($tag)
  }

  // 无标签时隐藏容器
  if (r.$tags.children.length === 0) {
    r.$tags.style.display = 'none'
  } else {
    r.$tags.style.display = ''
  }
}
