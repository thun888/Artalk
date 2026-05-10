package notify_pusher

import (
	"context"
	"net/http"
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
	customEndpoint string // 例如: https://tg.example.com
}

func (t *telegramEndpointRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Host, "api.telegram.org") {
		host := strings.TrimPrefix(strings.TrimPrefix(t.customEndpoint, "https://"), "http://")
		host = strings.TrimRight(host, "/")
		newURL := "https://" + host + req.URL.Path
		if req.URL.RawQuery != "" {
			newURL += "?" + req.URL.RawQuery
		}
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		log.Debug("[Notify] Telegram API request: ", newURL)
		return http.DefaultTransport.RoundTrip(newReq)
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
		var telegramService *telegram.Telegram
		if tgConf.ApiEndpoint != "" {
			// 自定义端点：直接构造 BotAPI，跳过 GetMe() 验证
			bot := &tgbotapi.BotAPI{
				Token:  tgConf.ApiToken,
				Client: &http.Client{Transport: &telegramEndpointRewriter{customEndpoint: tgConf.ApiEndpoint}},
				Buffer: 100,
			}
			telegramService = &telegram.Telegram{}
			telegramService.SetClient(bot)
			log.Info("[Notify] Telegram using custom API endpoint: ", tgConf.ApiEndpoint)
		} else {
			// 默认端点
			var err error
			telegramService, err = telegram.New(tgConf.ApiToken)
			if err != nil {
				log.Error("[Notify] Telegram service init error: ", err)
			}
		}
		if telegramService != nil {
			telegramService.AddReceivers(tgConf.Receivers...)
			helper.UseServices(telegramService)
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
