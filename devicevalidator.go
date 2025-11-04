// Package devicevalidator provides device validation header middleware for Caddy
// Repository: github.com/Juijote/Caddy-Device-Validator
package devicevalidator

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
	ExcludePaths []string `json:"exclude_paths,omitempty"`

	logger       *zap.Logger
	mobileRegex  *regexp.Regexp
	excludeRegex []*regexp.Regexp
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
	dv.mobileRegex = regexp.MustCompile(`(?i)Mobile`)

	for _, pattern := range dv.ExcludePaths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid exclude path pattern %s: %v", pattern, err)
		}
		dv.excludeRegex = append(dv.excludeRegex, re)
	}

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

	// 检查 Cookie 中的验证数据
	cookie, err := r.Cookie("_dv_data")
	if err == nil && cookie.Value != "" {
		// 解析 Cookie: touchPoints|hasTouch
		parts := strings.Split(cookie.Value, "|")
		if len(parts) == 2 {
			touchPoints := parts[0]
			hasTouch := parts[1]
			isFake := touchPoints == "0" || touchPoints == "1" || hasTouch == "false"

			// 添加请求头
			r.Header.Set("X-Device-Touch-Points", touchPoints)
			r.Header.Set("X-Device-Has-Touch", hasTouch)
			r.Header.Set("X-Device-Is-Fake-Mobile", fmt.Sprintf("%t", isFake))

			return next.ServeHTTP(w, r)
		}
	}

	// 检查是否是带验证数据的请求（从验证页面提交的）
	touchPoints := r.Header.Get("X-Device-Touch-Points")
	hasTouch := r.Header.Get("X-Device-Has-Touch")

	if touchPoints != "" && hasTouch != "" {
		// 设置 Cookie（Session Cookie，浏览器关闭后失效）
		cookieValue := touchPoints + "|" + hasTouch
		http.SetCookie(w, &http.Cookie{
			Name:     "_dv_data",
			Value:    cookieValue,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})

		isFake := touchPoints == "0" || touchPoints == "1" || hasTouch == "false"
		r.Header.Set("X-Device-Is-Fake-Mobile", fmt.Sprintf("%t", isFake))

		dv.logger.Debug("device validated",
			zap.String("touch_points", touchPoints),
			zap.String("has_touch", hasTouch),
			zap.Bool("is_fake", isFake),
		)

		return next.ServeHTTP(w, r)
	}

	// 没有验证数据，显示验证页面
	dv.serveValidationPage(w, r)
	return nil
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
const text="访问验证中...";
const cursor=document.createElement("span");
cursor.className="cursor";
cursor.textContent=" ";
terminal.appendChild(cursor);
let i=0;
function type(){if(i<text.length){cursor.insertAdjacentText("beforebegin",text[i]);i++;setTimeout(type,80);}else{setTimeout(redirect,500);}}
function redirect(){
fetch(window.location.href,{
method:"GET",
headers:{
"X-Device-Touch-Points":String(info.maxTouchPoints),
"X-Device-Has-Touch":String(info.hasTouch)
}
}).then(r=>r.text()).then(html=>{
document.open();
document.write(html);
document.close();
}).catch(()=>window.location.reload());
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

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (dv *DeviceValidatorHeader) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
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