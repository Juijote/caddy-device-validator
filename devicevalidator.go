// Package devicevalidator provides device validation middleware for Caddy
// Repository: github.com/Juijote/Caddy-Device-Validator
package devicevalidator

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(DeviceValidator{})
	httpcaddyfile.RegisterHandlerDirective("device_validator", parseCaddyfile)
}

// DeviceValidator 实现设备验证中间件
type DeviceValidator struct {
	Enable            bool     `json:"enable,omitempty"`
	CheckFakeMobile   bool     `json:"check_fake_mobile,omitempty"`
	CheckHeadless     bool     `json:"check_headless,omitempty"`
	ForceVerification bool     `json:"force_verification,omitempty"`
	DebugMode         bool     `json:"debug_mode,omitempty"`
	TokenExpiry       int      `json:"token_expiry,omitempty"`
	ExcludePaths      []string `json:"exclude_paths,omitempty"`
	CustomMessage     string   `json:"custom_message,omitempty"`

	tokens     map[string]*tokenData
	tokensLock sync.RWMutex
	logger     *zap.Logger

	mobileRegex  *regexp.Regexp
	excludeRegex []*regexp.Regexp
}

type tokenData struct {
	IP        string
	CreatedAt time.Time
	Valid     bool
}

func (DeviceValidator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.device_validator",
		New: func() caddy.Module { return new(DeviceValidator) },
	}
}

func (dv *DeviceValidator) Provision(ctx caddy.Context) error {
	dv.logger = ctx.Logger()
	dv.tokens = make(map[string]*tokenData)

	if dv.TokenExpiry == 0 {
		dv.TokenExpiry = 300
	}

	dv.mobileRegex = regexp.MustCompile(`(?i)Mobile|Android|iPhone|iPad|iPod`)

	for _, pattern := range dv.ExcludePaths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid exclude path pattern %s: %v", pattern, err)
		}
		dv.excludeRegex = append(dv.excludeRegex, re)
	}

	go dv.cleanupExpiredTokens()
	return nil
}

func (dv *DeviceValidator) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !dv.Enable {
		return next.ServeHTTP(w, r)
	}

	if dv.isExcludedPath(r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	token := r.URL.Query().Get("_vt")
	if token != "" {
		if dv.isValidToken(token, r.RemoteAddr) {
			newURL := r.URL
			q := newURL.Query()
			q.Del("_vt")
			newURL.RawQuery = q.Encode()

			http.SetCookie(w, &http.Cookie{
				Name:     "device_verified",
				Value:    "1",
				Path:     "/",
				MaxAge:   dv.TokenExpiry,
				HttpOnly: false,
				SameSite: http.SameSiteLaxMode,
			})

			if newURL.String() != r.URL.String() {
				http.Redirect(w, r, newURL.String(), http.StatusFound)
				return nil
			}
			return next.ServeHTTP(w, r)
		}
	}

	verifiedCookie, err := r.Cookie("device_verified")
	if err == nil && verifiedCookie.Value == "1" {
		return next.ServeHTTP(w, r)
	}

	if dv.ForceVerification {
		dv.serveValidationPage(w, r)
		return nil
	}

	if dv.isSuspiciousDevice(r) {
		dv.serveValidationPage(w, r)
		return nil
	}

	return next.ServeHTTP(w, r)
}

func (dv *DeviceValidator) isSuspiciousDevice(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	isMobileUA := dv.mobileRegex.MatchString(userAgent)

	verifiedCookie, hasVerified := r.Cookie("device_verified")
	if hasVerified == nil && verifiedCookie.Value == "1" {
		return false
	}

	if dv.CheckHeadless {
		if strings.Contains(userAgent, "HeadlessChrome") || strings.Contains(userAgent, "PhantomJS") {
			return true
		}
	}

	if dv.CheckFakeMobile && isMobileUA {
		return true
	}

	return false
}

func (dv *DeviceValidator) serveValidationPage(w http.ResponseWriter, r *http.Request) {
	token := dv.generateToken(r.RemoteAddr)
	message := dv.CustomMessage
	if message == "" {
		message = "检测到异常设备特征，请使用真实设备访问"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>设备验证</title>
<style>
body {
	font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
	background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
	display: flex;
	align-items: center;
	justify-content: center;
	height: 100vh;
}
.container {
	background: white;
	padding: 40px;
	border-radius: 20px;
	box-shadow: 0 20px 60px rgba(0,0,0,0.3);
	text-align: center;
}
.spinner {
	border: 4px solid #f3f3f3;
	border-top: 4px solid #667eea;
	border-radius: 50%%;
	width: 50px;
	height: 50px;
	animation: spin 1s linear infinite;
	margin: 20px auto;
}
@keyframes spin {
	0%% { transform: rotate(0deg); }
	100%% { transform: rotate(360deg); }
}
</style>
</head>
<body>
<div class="container">
<h2>正在验证设备</h2>
<div class="spinner"></div>
<p>请稍候...</p>
<div id="debug" style="display:none;"></div>
</div>
<script>
(function() {
	let isSuspicious = false;
	let reasons = [];

	const info = {
		ua: navigator.userAgent,
		hasTouch: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
		maxTouchPoints: navigator.maxTouchPoints || 0
	};

	// 模拟移动设备但无触控能力 → 伪造
	if (/Mobile|Android|iPhone|iPad/i.test(info.ua) && info.maxTouchPoints <= 1) {
		isSuspicious = true;
		reasons.push('移动 UA 但触控点 ≤ 1，疑似 F12 模拟设备');
	}

	// 无头浏览器检测
	if (navigator.webdriver === true) {
		isSuspicious = true;
		reasons.push('检测到 WebDriver 环境');
	}

	if (isSuspicious) {
		document.body.innerHTML = '<div class="container"><h2>访问被拒绝</h2><p>%s</p><p style="color:#999;font-size:12px;">原因: ' + reasons.join(', ') + '</p></div>';
	} else {
		document.cookie = 'device_verified=1; path=/; max-age=300; SameSite=Lax';
		const url = new URL(window.location.href);
		url.searchParams.set('_vt', '%s');
		setTimeout(() => { window.location.href = url.toString(); }, 500);
	}
})();
</script>
</body>
</html>`, message, token)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (dv *DeviceValidator) generateToken(ip string) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	dv.tokensLock.Lock()
	dv.tokens[token] = &tokenData{IP: ip, CreatedAt: time.Now(), Valid: true}
	dv.tokensLock.Unlock()
	return token
}

func (dv *DeviceValidator) isValidToken(token, ip string) bool {
	dv.tokensLock.RLock()
	defer dv.tokensLock.RUnlock()
	data, exists := dv.tokens[token]
	if !exists {
		return false
	}
	if time.Since(data.CreatedAt).Seconds() > float64(dv.TokenExpiry) {
		return false
	}
	if strings.Split(data.IP, ":")[0] != strings.Split(ip, ":")[0] {
		return false
	}
	return data.Valid
}

func (dv *DeviceValidator) isExcludedPath(path string) bool {
	for _, re := range dv.excludeRegex {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (dv *DeviceValidator) cleanupExpiredTokens() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		dv.tokensLock.Lock()
		now := time.Now()
		for token, data := range dv.tokens {
			if now.Sub(data.CreatedAt).Seconds() > float64(dv.TokenExpiry) {
				delete(dv.tokens, token)
			}
		}
		dv.tokensLock.Unlock()
	}
}

func (dv *DeviceValidator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "enable":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.Enable = d.Val() == "true"

			case "check_fake_mobile":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.CheckFakeMobile = d.Val() == "true"

			case "check_headless":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.CheckHeadless = d.Val() == "true"

			case "force_verification":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.ForceVerification = d.Val() == "true"

			case "debug_mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.DebugMode = d.Val() == "true"

			case "token_expiry":
				if !d.NextArg() {
					return d.ArgErr()
				}
				fmt.Sscanf(d.Val(), "%d", &dv.TokenExpiry)

			case "exclude_paths":
				dv.ExcludePaths = d.RemainingArgs()

			case "custom_message":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.CustomMessage = d.Val()

			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var dv DeviceValidator
	err := dv.UnmarshalCaddyfile(h.Dispenser)
	return &dv, err
}

var (
	_ caddy.Provisioner           = (*DeviceValidator)(nil)
	_ caddyhttp.MiddlewareHandler = (*DeviceValidator)(nil)
	_ caddyfile.Unmarshaler       = (*DeviceValidator)(nil)
)
