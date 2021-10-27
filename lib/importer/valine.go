package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ArtalkJS/ArtalkGo/lib"
	"github.com/ArtalkJS/ArtalkGo/model"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/sirupsen/logrus"
)

var ValineImporter = &_ValineImporter{
	ImporterInfo: ImporterInfo{
		Name: "valine",
		Desc: "从 Valine 导入数据",
		Note: "",
	},
}

type _ValineImporter struct {
	ImporterInfo
}

func (imp *_ValineImporter) Run(basic *BasicParams, payload []string) {
	RequiredBasicTargetSite(basic)

	// 读取文件
	jsonStr := JsonFileReady(payload)

	// 解析 JSON
	comments, err := ParseValineCommentJSON(jsonStr)
	if err != nil {
		logrus.Fatal("json 解析失败：", err)
	}

	ImportValine(basic, payload, comments)
}

func ImportValine(basic *BasicParams, payload []string, comments []ValineComment) {
	// 汇总
	fmt.Print("# 请过目：\n\n")

	// 第一条评论
	if len(comments) > 0 {
		fmt.Printf("[第一条评论]\n\n"+
			"    %#v\n\n", comments[0])
	}

	PrintTable([]table.Row{
		{"目标站点名", basic.TargetSiteName},
		{"目标站点 URL", basic.TargetSiteUrl},
		{"评论数量", len(comments)},
	})

	fmt.Print("\n")

	// 确认开始
	if !Confirm("确认开始导入吗？") {
		os.Exit(0)
	}

	// 准备导入评论
	fmt.Print("\n")

	SiteReady(basic)
	ImportValineComments(basic, comments)
}

func ParseValineCommentJSON(jsonStr string) ([]ValineComment, error) {
	var list []ValineComment
	err := json.Unmarshal([]byte(lib.JsonArrItemAnyWrapInStr(jsonStr)), &list)
	if err != nil {
		return []ValineComment{}, err
	}

	return list, nil
}

// PageKey (c.Url 不确定是否为完整 URL 还是一个 path)
func GetValineNewPageKey(baseUrl string, c ValineComment) string {
	baseUrl = strings.TrimSuffix(baseUrl, "/") + "/"
	return baseUrl + strings.TrimPrefix(lib.GetUrlWithoutDomain(c.Url), "/")
}

func ImportValineComments(basic *BasicParams, comments []ValineComment) {
	siteName := basic.TargetSiteName

	idMap := map[string]int{}    // ID映射 object_id => id
	idChanges := map[uint]uint{} // 变更 ID original_id => new_db_id

	id := 1
	for _, c := range comments {
		idMap[c.ObjectId] = id
		id++
	}

	for _, c := range comments {

		// 创建 user
		user := model.FindCreateUser(c.Nick, c.Mail, c.Link)

		// 创建 page
		pageKey := GetValineNewPageKey(basic.TargetSiteUrl, c)
		page := model.FindCreatePage(pageKey, "", siteName)

		// 创建新 comment 实例
		nComment := model.Comment{
			Content: c.Comment,

			PageKey:  page.Key,
			SiteName: basic.TargetSiteName,

			UserID: user.ID,
			UA:     c.UA,
			IP:     c.IP,

			Rid: uint(idMap[c.Rid]),

			IsCollapsed: false,
			IsPending:   false,
		}

		// 日期恢复
		createdVal := fmt.Sprintf("%v", c.CreatedAt)
		updatedVal := fmt.Sprintf("%v", c.UpdatedAt)
		nComment.CreatedAt = ParseDate(createdVal)
		nComment.UpdatedAt = ParseDate(updatedVal)

		// 保存到数据库
		err := lib.DB.Create(&nComment).Error
		if err != nil {
			logrus.Error(fmt.Sprintf("评论源 ID:%s 保存失败", c.ObjectId))
			continue
		}

		idChanges[uint(idMap[c.ObjectId])] = nComment.ID
	}

	// reply id 重建
	RebuildRid(idChanges)

	fmt.Print("\n")
	logrus.Info("RID 重构完毕")
}

type ValineComment struct {
	ObjectId  string `json:"objectId"`
	Nick      string `json:"nick"`
	IP        string `json:"ip"`
	Mail      string `json:"mail"`
	MailMd5   string `json:"mailMd5"`
	IsSpam    string `json:"isSpam"`
	UA        string `json:"ua"`
	Link      string `json:"link"`
	Pid       string `json:"pid"`
	Rid       string `json:"rid"`
	Comment   string `json:"comment"`
	Url       string `json:"url"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}
