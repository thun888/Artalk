package email

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"gopkg.in/gomail.v2"
)

func getCookedEmail(email *Email) *gomail.Message {
	m := gomail.NewMessage()

	// 发送人
	m.SetHeader("From", m.FormatAddress(email.FromAddr, email.FromName))
	// 接收人
	m.SetHeader("To", email.ToAddr)
	// 抄送人
	//m.SetAddressHeader("Cc", "dan@example.com", "Dan")
	// 主题
	m.SetHeader("Subject", email.Subject)
	// Message-ID (RFC 5322)
	m.SetHeader("Message-ID", fmt.Sprintf("<%d.%s@%s>",
		time.Now().UnixNano(),
		randomString(16),
		extractDomain(email.FromAddr),
	))
	// 内容
	m.SetBody("text/html", email.Body)
	// 附件
	//m.Attach("./file.png")

	return m
}

func getEmailMineTxt(email *Email) string {
	emailBuffer := bytes.NewBuffer([]byte{})
	getCookedEmail(email).WriteTo(emailBuffer)
	return string(emailBuffer.Bytes()[:])
}

func extractDomain(addr string) string {
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 && parts[1] != "" {
		return parts[1]
	}
	return "localhost"
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
