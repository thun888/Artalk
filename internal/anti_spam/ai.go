package anti_spam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/artalkjs/artalk/v2/internal/log"
)

// 将 (*AIChecker) 类型的 nil 指针赋值给 Checker 接口类型的空标识符 _。如果 *AIChecker 没有实现 Checker 接口的所有方法，编译就会报错。
var _ Checker = (*AIChecker)(nil)

const (
	aiHTTPTimeout          = 300 * time.Second
	aiMaxContentRunes      = 2000
	aiRespMaxBytesNormal   = 1024
	aiRespMaxBytesThinking = 64 * 1024
)

func (c *AIChecker) respMaxBytes() int64 {
	if c.conf.Thinking {
		return aiRespMaxBytesThinking
	}
	return aiRespMaxBytesNormal
}

type AICheckerConf struct {
	Type         string
	Endpoint     string
	ApiKey       string
	Model        string
	SystemPrompt string // system message
	UserPrompt   string // user message template (supports placeholders)
	Thinking     bool
	MaxTokens    int
}

type AIChecker struct {
	conf   *AICheckerConf
	client *http.Client
}

func NewAIChecker(conf *AICheckerConf) Checker {
	return &AIChecker{
		conf:   conf,
		client: &http.Client{Timeout: aiHTTPTimeout},
	}
}

func (*AIChecker) Name() string {
	return "ai"
}

func (c *AIChecker) Check(p *CheckerParams) (bool, error) {
	systemMsg, userMsg := c.buildMessages(p)

	var (
		respText string
		err      error
	)

	switch strings.ToLower(c.conf.Type) {
	case "openai":
		respText, err = c.callOpenAI(systemMsg, userMsg)
	case "anthropic":
		respText, err = c.callAnthropic(systemMsg, userMsg)
	default:
		return false, fmt.Errorf("unsupported ai type: %s", c.conf.Type)
	}

	if err != nil {
		return false, err
	}

	log.Debug(LOG_TAG+"AI response: ", respText)

	isSpam, reason, err := parseAIJudgement(respText)
	if err != nil {
		return false, err
	}
	if isSpam {
		log.Info(LOG_TAG+"AI detected spam: ", reason)
		return false, nil
	}
	return true, nil
}

// buildMessages returns the system message (verbatim from config) and the
// user message (with placeholder replacement applied to UserPrompt).
// If UserPrompt is empty, the comment content is used as the user message.
func (c *AIChecker) buildMessages(p *CheckerParams) (system, user string) {
	system = c.conf.SystemPrompt

	replacements := map[string]string{
		"{{content}}":  truncateText(p.Content, aiMaxContentRunes),
		"{{username}}": p.UserName,
		"{{email}}":    p.UserEmail,
		"{{ip}}":       p.UserIP,
		"{{ua}}":       p.UserAgent,
		"{{blog_url}}": p.BlogURL,
	}

	if c.conf.UserPrompt != "" {
		user = c.conf.UserPrompt
		for placeholder, value := range replacements {
			user = strings.ReplaceAll(user, placeholder, value)
		}
	} else {
		user = truncateText(p.Content, aiMaxContentRunes)
	}

	return system, user
}

// aiJudgement is the expected JSON schema from the AI model.
type aiJudgement struct {
	Result bool   `json:"result"`
	Reason string `json:"reason"`
}

// parseAIJudgement parses the AI response as a strict JSON object.
// Expected format: {"result": true/false, "reason": "..."}
// result=true means spam, result=false means not spam.
func parseAIJudgement(respText string) (bool, string, error) {
	trimmed := cleanAIResponse(respText)

	var j aiJudgement
	if err := json.Unmarshal([]byte(trimmed), &j); err != nil {
		return false, "", fmt.Errorf("ai response is not valid JSON: %w (raw: %s)", err, respText)
	}

	return j.Result, j.Reason, nil
}

// cleanAIResponse strips thinking tags and markdown code fences from the AI response,
// extracting only the JSON payload.
func cleanAIResponse(text string) string {
	// Remove <think>...</think> blocks (non-greedy)
	for {
		start := strings.Index(text, "<think>")
		if start == -1 {
			break
		}
		end := strings.Index(text[start:], "</think>")
		if end == -1 {
			// No closing tag, remove everything from <think> onwards
			text = text[:start]
			break
		}
		text = text[:start] + text[start+end+8:]
	}

	text = strings.TrimSpace(text)

	// Strip markdown code fences: ```json ... ``` or ``` ... ```
	if strings.HasPrefix(text, "```") {
		// Find first newline after opening fence
		if nl := strings.Index(text, "\n"); nl != -1 {
			text = text[nl+1:]
		}
		// Remove trailing closing fence
		if idx := strings.LastIndex(text, "```"); idx != -1 {
			text = text[:idx]
		}
		text = strings.TrimSpace(text)
	}

	return text
}

// truncateText truncates text to maxRunes characters, appending "..." if truncated.
func truncateText(text string, maxRunes int) string {
	if utf8.RuneCountInString(text) <= maxRunes {
		return text
	}
	runes := []rune(text)
	return string(runes[:maxRunes]) + "..."
}

// --- OpenAI API ---

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	//nolint:tagliatelle
	MaxTokens int `json:"max_tokens,omitempty"`
	//nolint:tagliatelle
	Reasoning *openAIReasoning `json:"reasoning,omitempty"`
}

type openAIReasoning struct {
	Effort string `json:"effort"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (c *AIChecker) callOpenAI(systemMsg, userMsg string) (string, error) {
	messages := []openAIMessage{
		{Role: "system", Content: systemMsg},
		{Role: "user", Content: userMsg},
	}

	reqBody := openAIRequest{
		Model:     c.conf.Model,
		Messages:  messages,
		MaxTokens: c.conf.MaxTokens,
	}

	if c.conf.Thinking {
		reqBody.Reasoning = &openAIReasoning{Effort: "medium"}
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.conf.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.conf.ApiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, c.respMaxBytes()))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai api returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result openAIResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse openai response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai response has no choices")
	}

	return result.Choices[0].Message.Content, nil
}

// --- Anthropic API ---

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	System    string             `json:"system,omitempty"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
	Thinking  *anthropicThinking `json:"thinking,omitempty"`
}

type anthropicThinking struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func (c *AIChecker) callAnthropic(systemMsg, userMsg string) (string, error) {
	maxTokens := c.conf.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1024
	}

	reqBody := anthropicRequest{
		Model:     c.conf.Model,
		System:    systemMsg,
		MaxTokens: maxTokens,
		Messages: []anthropicMessage{
			{Role: "user", Content: userMsg},
		},
	}

	if c.conf.Thinking {
		reqBody.Thinking = &anthropicThinking{
			Type:         "enabled",
			BudgetTokens: maxTokens / 2,
		}
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.conf.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.conf.ApiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, c.respMaxBytes()))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic api returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result anthropicResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse anthropic response: %w", err)
	}

	// Extract text from content blocks (skip thinking blocks)
	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}

	return "", fmt.Errorf("anthropic response has no text content")
}
