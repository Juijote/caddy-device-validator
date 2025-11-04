// Package devicevalidator provides device validation header middleware for Caddy
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
	caddy.RegisterModule(DeviceValidatorHeader{})
	httpcaddyfile.RegisterHandlerDirective("device_validator_header", parseCaddyfile)
}

// DeviceValidatorHeader 实现设备验证请求头中间件
type DeviceValidatorHeader struct {
	SessionExpiry int      `json:"session_expiry,omitempty"`
	ExcludePaths  []string `json:"exclude_paths,omitempty"`

	sessions     map[string]*sessionData
	sessionsLock sync.RWMutex
	logger       *zap.Logger
	mobileRegex  *regexp.Regexp
	excludeRegex []*regexp.Regexp
}

type sessionData struct {
	IP           string
	CreatedAt    time.Time
	TouchPoints  string
	HasTouch     string
	IsFakeMobile bool
	Verified     bool
}

// CaddyModule returns the Caddy module information.
func (DeviceValidatorHeader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.device_validator_header",
		New: func() caddy.Module { return new(DeviceValidatorHeader) },
	}
}

// Provision implements caddy.Provisioner.
func (dv *DeviceValidatorHeader) Provision(ctx caddy.Context) error {
	dv.logger = ctx.Logger()
	dv.sessions = make(map[string]*sessionData)

	if dv.SessionExpiry == 0 {
		dv.SessionExpiry = 300
	}

	dv.mobileRegex = regexp.MustCompile(`(?i)Mobile`)

	for _, pattern := range dv.ExcludePaths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid exclude path pattern %s: %v", pattern, err)
		}
		dv.excludeRegex = append(dv.excludeRegex, re)
	}

	go dv.cleanupExpiredSessions()
	return nil
}

// Validate implements caddy.Validator.
func (dv *DeviceValidatorHeader) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (dv *DeviceValidatorHeader) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 如果路径被排除,跳过检查
	if dv.isExcludedPath(r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	userAgent := r.Header.Get("User-Agent")
	isMobileUA := dv.mobileRegex.MatchString(userAgent)

	// 只检查移动设备 UA
	if !isMobileUA {
		return next.ServeHTTP(w, r)
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	sessionKey := dv.getSessionKey(clientIP)

	// 检查是否是验证提交请求
	if r.Method == "POST" && r.Header.Get("X-Device-Validation") == "submit" {
		touchPoints := r.FormValue("touch_points")
		hasTouch := r.FormValue("has_touch")

		// 创建或更新会话
		dv.sessionsLock.Lock()
		isFake := touchPoints == "0" || touchPoints == "1" || hasTouch == "false"
		dv.sessions[sessionKey] = &sessionData{
			IP:           clientIP,
			CreatedAt:    time.Now(),
			TouchPoints:  touchPoints,
			HasTouch:     hasTouch,
			IsFakeMobile: isFake,
			Verified:     true,
		}
		dv.sessionsLock.Unlock()

		// 返回成功响应
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		return nil
	}

	// 检查是否已验证
	dv.sessionsLock.RLock()
	session, exists := dv.sessions[sessionKey]
	dv.sessionsLock.RUnlock()

	if exists && session.Verified && time.Since(session.CreatedAt).Seconds() <= float64(dv.SessionExpiry) {
		// 已验证,添加请求头(仅内部使用,不会发送给客户端)
		r.Header.Set("X-Device-Touch-Points", session.TouchPoints)
		r.Header.Set("X-Device-Has-Touch", session.HasTouch)
		r.Header.Set("X-Device-Is-Fake-Mobile", fmt.Sprintf("%t", session.IsFakeMobile))
		return next.ServeHTTP(w, r)
	}

	// 未验证,显示验证页面
	dv.serveValidationPage(w, r)
	return nil
}

// getSessionKey 生成会话密钥
func (dv *DeviceValidatorHeader) getSessionKey(ip string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return ip + "_" + hex.EncodeToString(b)[:8]
}

// serveValidationPage 显示验证页面
func (dv *DeviceValidatorHeader) serveValidationPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>访问</title>
<style>
body{margin:0;height:100vh;font-family:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background-color:#000;background-image:radial-gradient(#11581E,#041607);color:#80ff80;text-shadow:0 0 2px #33ff33,0 0 1px #33ff33;display:flex;align-items:center;justify-content:center;overflow:hidden;font-size:1.5rem;}
.noise{position:fixed;top:0;left:0;width:100%;height:100%;background:repeating-radial-gradient(#000 0 0.0001%,#fff 0 0.0002%) 50% 0/2000px 2000px,repeating-conic-gradient(#000 0 0.0001%,#fff 0 0.0002%) 50% 50%/2000px 2000px;background-blend-mode:difference;animation:noise .3s infinite alternate;opacity:.03;pointer-events:none;z-index:-1;}
.overlay{pointer-events:none;position:fixed;width:100%;height:100%;background:repeating-linear-gradient(180deg,rgba(0,0,0,0) 0,rgba(0,0,0,.3) 50%,rgba(0,0,0,0) 100%);background-size:auto 3px;z-index:1;}
.overlay::before{content:"";position:absolute;inset:0;background-image:linear-gradient(0deg,transparent 0%,rgba(32,128,32,.8) 2%,rgba(32,128,32,.8) 3%,transparent 100%);background-repeat:no-repeat;animation:scan 5s linear infinite;}
.terminal{position:relative;max-width:600px;margin:0 auto;padding:20px;text-align:center;white-space:pre;}
.cursor{display:inline-block;width:.8ch;background:#80ff80;animation:blink 1s steps(2,start) infinite;vertical-align:bottom;}
@keyframes scan{0%{background-position:0 -100vh}100%{background-position:0 100vh}}
@keyframes noise{0%{transform:translate(0,0)}100%{transform:translate(1px,1px)}}
@keyframes blink{0%,50%{background:#80ff80}50.1%,100%{background:transparent}}
@media(prefers-reduced-motion:reduce){.noise,.overlay::before,.cursor{animation:none}}
</style>
</head>
<body>
<div class="noise"></div>
<div class="overlay"></div>
<main class="terminal" id="terminal"></main>
<script>
(function(){
const terminal=document.getElementById("terminal");
const info={hasTouch:'ontouchstart' in window||navigator.maxTouchPoints>0,maxTouchPoints:navigator.maxTouchPoints||0};
const text="访问中...";
const cursor=document.createElement("span");
cursor.className="cursor";
cursor.textContent=" ";
terminal.appendChild(cursor);
let i=0;
function type(){if(i<text.length){cursor.insertAdjacentText("beforebegin",text[i]);i++;setTimeout(type,80);}else{setTimeout(submit,500);}}
function submit(){
const formData=new FormData();
formData.append("touch_points",info.maxTouchPoints);
formData.append("has_touch",info.hasTouch);
fetch(window.location.href,{method:"POST",headers:{"X-Device-Validation":"submit"},body:formData})
.then(r=>r.json())
.then(()=>window.location.reload())
.catch(()=>window.location.reload());
}
type();
})();
</script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// isExcludedPath 检查路径是否被排除
func (dv *DeviceValidatorHeader) isExcludedPath(path string) bool {
	for _, re := range dv.excludeRegex {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// cleanupExpiredSessions 清理过期会话
func (dv *DeviceValidatorHeader) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		dv.sessionsLock.Lock()
		now := time.Now()
		for key, session := range dv.sessions {
			if now.Sub(session.CreatedAt).Seconds() > float64(dv.SessionExpiry) {
				delete(dv.sessions, key)
			}
		}
		dv.sessionsLock.Unlock()
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (dv *DeviceValidatorHeader) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "session_expiry":
				if !d.NextArg() {
					return d.ArgErr()
				}
				fmt.Sscanf(d.Val(), "%d", &dv.SessionExpiry)

			case "exclude_paths":
				dv.ExcludePaths = d.RemainingArgs()

			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new DeviceValidatorHeader.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var dv DeviceValidatorHeader
	err := dv.UnmarshalCaddyfile(h.Dispenser)
	return &dv, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*DeviceValidatorHeader)(nil)
	_ caddy.Validator             = (*DeviceValidatorHeader)(nil)
	_ caddyhttp.MiddlewareHandler = (*DeviceValidatorHeader)(nil)
	_ caddyfile.Unmarshaler       = (*DeviceValidatorHeader)(nil)
)