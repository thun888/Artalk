package notify_pusher

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/artalkjs/artalk/v2/internal/config"
	"github.com/artalkjs/artalk/v2/internal/dao"
	"github.com/artalkjs/artalk/v2/internal/entity"
	"github.com/artalkjs/artalk/v2/internal/log"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/nikoksr/notify"
	"github.com/nikoksr/notify/service/dingding"
	"github.com/nikoksr/notify/service/line"
	"github.com/nikoksr/notify/service/slack"
	"github.com/nikoksr/notify/service/telegram"
)

// telegramEndpointRewriter 自定义 HTTP transport，将 Telegram API 请求重定向到自定义端点
type telegramEndpointRewriter struct {
	customEndpoint string // 格式: https://tg.example.com/bot%s/%s
}

func (t *telegramEndpointRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Host, "api.telegram.org") && strings.HasPrefix(req.URL.Path, "/bot") {
		// 从原始 URL 提取 token 和 method: /bot<TOKEN>/<method>
		pathParts := strings.SplitN(req.URL.Path[4:], "/", 2)
		if len(pathParts) == 2 {
			token := pathParts[0]
			method := pathParts[1]
			// 使用自定义端点格式重写 URL
			newURL := fmt.Sprintf(t.customEndpoint, token, method)
			parsedURL, err := url.Parse(newURL)
			if err == nil {
				req.URL = parsedURL
			}
		}
	}
	return http.DefaultTransport.RoundTrip(req)
}

type NotifyPusherConf struct {
	config.AdminNotifyConf
	Dao *dao.Dao

	// Provide a custom function to bridge the gap between Notify pusher and Email pusher
	EmailPush func(notify *entity.Notify) error
}

type NotifyPusher struct {
	conf   *NotifyPusherConf
	dao    *dao.Dao
	ctx    context.Context
	helper *notify.Notify
}

func NewNotifyPusher(conf *NotifyPusherConf) *NotifyPusher {
	pusher := &NotifyPusher{
		conf:   conf,
		dao:    conf.Dao,
		ctx:    context.Background(),
		helper: notify.New(),
	}

	pusher.loadHelper()

	return pusher
}

func (pusher *NotifyPusher) loadHelper() {
	var (
		helper = pusher.helper
		conf   = pusher.conf
	)

	// Telegram
	tgConf := conf.Telegram
	if tgConf.Enabled {
		if telegramService, err := telegram.New(tgConf.ApiToken); err == nil {
			// 自定义 Telegram Bot API 端点
			if tgConf.ApiEndpoint != "" {
				bot, err := tgbotapi.NewBotAPIWithClient(tgConf.ApiToken, &http.Client{
					Transport: &telegramEndpointRewriter{customEndpoint: tgConf.ApiEndpoint},
				})
				if err == nil {
					telegramService.SetClient(bot)
				} else {
					log.Error("[Notify] Telegram custom endpoint init error: ", err)
				}
			}
			telegramService.AddReceivers(tgConf.Receivers...)
			telegramService.SetParseMode("ModeMarkdown")
			helper.UseServices(telegramService)
		} else {
			log.Error("[Notify] Telegram service init error: ", err)
		}
	}

	// 钉钉
	dingTalkConf := conf.DingTalk
	if dingTalkConf.Enabled {
		dingTalkService := dingding.New(&dingding.Config{Token: dingTalkConf.Token, Secret: dingTalkConf.Secret})
		helper.UseServices(dingTalkService)
	}

	// Slack
	slackConf := conf.Slack
	if slackConf.Enabled {
		slackService := slack.New(slackConf.OauthToken)
		slackService.AddReceivers(slackConf.Receivers...)
		helper.UseServices(slackService)
	}

	// LINE
	LINEConf := conf.LINE
	if LINEConf.Enabled {
		if lineService, err := line.New(pusher.conf.LINE.ChannelSecret, pusher.conf.LINE.ChannelAccessToken); err == nil {
			lineService.AddReceivers(LINEConf.Receivers...)
			helper.UseServices(lineService)
		} else {
			log.Error("[Notify] LINE service init error: ", err)
		}
	}
}
