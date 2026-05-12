package entity

type CookedSite struct {
	ID                           uint     `json:"id"`
	Name                         string   `json:"name"`
	Urls                         []string `json:"urls"`
	UrlsRaw                      string   `json:"urls_raw"`
	FirstUrl                     string   `json:"first_url"`
	ExternalLinkRedirectTemplate string   `json:"external_link_redirect_template,omitempty"`
}
