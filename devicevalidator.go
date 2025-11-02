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
)

func init() {
	caddy.RegisterModule(DeviceValidator{})
	httpcaddyfile.RegisterHandlerDirective("device_validator", parseCaddyfile)
}

// DeviceValidator 实现设备验证中间件 
type DeviceValidator struct {
	// 配置项
	Enable          bool     `json:"enable,omitempty"`
	CheckDevTools   bool     `json:"check_devtools,omitempty"`
	CheckFakeMobile bool     `json:"check_fake_mobile,omitempty"`
	TokenExpiry     int      `json:"token_expiry,omitempty"` // 秒
	ExcludePaths    []string `json:"exclude_paths,omitempty"`
	CustomMessage   string   `json:"custom_message,omitempty"`

	// 运行时数据
	tokens     map[string]*tokenData
	tokensLock sync.RWMutex
	logger     *caddy.Logger

	// 编译后的正则
	mobileRegex  *regexp.Regexp
	excludeRegex []*regexp.Regexp
}

type tokenData struct {
	IP        string
	CreatedAt time.Time
	Valid     bool
}

// CaddyModule 返回 Caddy 模块信息
func (DeviceValidator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.device_validator",
		New: func() caddy.Module { return new(DeviceValidator) },
	}
}

// Provision 初始化模块
func (dv *DeviceValidator) Provision(ctx caddy.Context) error {
	dv.logger = ctx.Logger(dv)
	dv.tokens = make(map[string]*tokenData)

	// 设置默认值
	if dv.TokenExpiry == 0 {
		dv.TokenExpiry = 300 // 5分钟
	}

	// 编译正则表达式
	dv.mobileRegex = regexp.MustCompile(`(?i)Mobile|Android|iPhone|iPad|iPod`)

	// 编译排除路径
	for _, pattern := range dv.ExcludePaths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid exclude path pattern %s: %v", pattern, err)
		}
		dv.excludeRegex = append(dv.excludeRegex, re)
	}

	// 启动清理过期 token 的协程
	go dv.cleanupExpiredTokens()

	return nil
}

// ServeHTTP 实现 HTTP 处理
func (dv *DeviceValidator) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !dv.Enable {
		return next.ServeHTTP(w, r)
	}

	// 检查是否在排除路径中
	if dv.isExcludedPath(r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	// 检查是否有有效的验证 token
	token := r.URL.Query().Get("_vt")
	if token != "" && dv.isValidToken(token, r.RemoteAddr) {
		// Token 有效,继续处理请求
		return next.ServeHTTP(w, r)
	}

	// 检查设备是否可疑
	if dv.isSuspiciousDevice(r) {
		// 返回验证页面
		dv.serveValidationPage(w, r)
		return nil
	}

	// 正常请求,继续处理
	return next.ServeHTTP(w, r)
}

// isSuspiciousDevice 检测是否为可疑设备
func (dv *DeviceValidator) isSuspiciousDevice(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")

	// 检查是否为移动设备 UA
	isMobileUA := dv.mobileRegex.MatchString(userAgent)

	if !isMobileUA {
		return false
	}

	// 检查 Client Hints (现代浏览器支持)
	if dv.CheckFakeMobile {
		secChUaMobile := r.Header.Get("Sec-CH-UA-Mobile")
		secChUaPlatform := r.Header.Get("Sec-CH-UA-Platform")

		// 如果声称是移动设备但 Client Hints 说不是
		if secChUaMobile == "?0" {
			dv.logger.Info("detected fake mobile device via Client Hints",
				"ua", userAgent,
				"sec-ch-ua-mobile", secChUaMobile)
			return true
		}

		// 桌面平台但有移动 UA
		if secChUaPlatform != "" {
			platformLower := strings.ToLower(secChUaPlatform)
			if (strings.Contains(platformLower, "windows") ||
				strings.Contains(platformLower, "macos") ||
				strings.Contains(platformLower, "linux")) && isMobileUA {
				dv.logger.Info("detected desktop platform with mobile UA",
					"ua", userAgent,
					"platform", secChUaPlatform)
				return true
			}
		}
	}

	// 检查 cookie 中的屏幕宽度信息
	if cookie, err := r.Cookie("screen_width"); err == nil {
		var width int
		fmt.Sscanf(cookie.Value, "%d", &width)
		if width > 768 && isMobileUA {
			dv.logger.Info("detected large screen with mobile UA",
				"ua", userAgent,
				"screen_width", width)
			return true
		}
	}

	return false
}

// serveValidationPage 返回验证页面
func (dv *DeviceValidator) serveValidationPage(w http.ResponseWriter, r *http.Request) {
	token := dv.generateToken(r.RemoteAddr)

	message := dv.CustomMessage
	if message == "" {
		message = "检测到异常设备特征,请使用真实设备访问"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>设备验证</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%%;
            text-align: center;
        }
        h2 { 
            color: #333; 
            margin-bottom: 20px;
            font-size: 24px;
        }
        .loading { 
            color: #666; 
            font-size: 16px;
            margin: 20px 0;
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
        .denied { 
            color: #d32f2f; 
            font-size: 18px;
            margin-top: 20px;
        }
        .icon { font-size: 48px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔍</div>
        <h2>正在验证设备</h2>
        <div class="spinner"></div>
        <p class="loading">请稍候...</p>
    </div>
    
    <script>
        (function() {
            // 收集设备信息
            const deviceInfo = {
                screenWidth: window.screen.width,
                screenHeight: window.screen.height,
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight,
                outerWidth: window.outerWidth,
                outerHeight: window.outerHeight,
                hasTouch: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
                maxTouchPoints: navigator.maxTouchPoints || 0,
                devicePixelRatio: window.devicePixelRatio,
                orientation: screen.orientation?.type || 'unknown'
            };
            
            let isSuspicious = false;
            let reason = '';
            
            // 检测 DevTools (多种方法)
            %s
            
            // 检测是否为伪造的移动设备
            const isMobileUA = /Mobile|Android|iPhone|iPad/i.test(navigator.userAgent);
            const hasSmallScreen = deviceInfo.screenWidth <= 768;
            const isFakeMobile = isMobileUA && !deviceInfo.hasTouch && !hasSmallScreen;
            
            if (isFakeMobile) {
                isSuspicious = true;
                reason = '移动设备UA但无触摸支持且屏幕较大';
            }
            
            if (isSuspicious) {
                document.querySelector('.container').innerHTML = 
                    '<div class="icon">⛔</div>' +
                    '<h2 class="denied">访问被拒绝</h2>' +
                    '<p class="denied">%s</p>' +
                    '<p style="color: #999; font-size: 12px; margin-top: 20px;">原因: ' + reason + '</p>';
            } else {
                // 设置 cookie 并重定向
                document.cookie = 'screen_width=' + deviceInfo.screenWidth + '; path=/; max-age=300; SameSite=Lax';
                document.cookie = 'device_verified=1; path=/; max-age=300; SameSite=Lax';
                
                // 添加验证参数后重定向
                const url = new URL(window.location.href);
                url.searchParams.set('_vt', '%s');
                
                setTimeout(() => {
                    window.location.href = url.toString();
                }, 500);
            }
        })();
    </script>
</body>
</html>`, dv.getDevToolsDetectionJS(), message, token)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// getDevToolsDetectionJS 返回 DevTools 检测 JS 代码
func (dv *DeviceValidator) getDevToolsDetectionJS() string {
	if !dv.CheckDevTools {
		return "// DevTools detection disabled"
	}

	return `
            // 方法1: 窗口尺寸差异检测
            const threshold = 160;
            const widthDiff = deviceInfo.outerWidth - deviceInfo.innerWidth;
            const heightDiff = deviceInfo.outerHeight - deviceInfo.innerHeight;
            
            if (widthDiff > threshold || heightDiff > threshold) {
                isSuspicious = true;
                reason = '检测到开发者工具';
            }
            
            // 方法2: 时间差异检测
            const start = performance.now();
            debugger;
            const end = performance.now();
            
            if (end - start > 100) {
                isSuspicious = true;
                reason = '检测到调试器';
            }
            
            // 方法3: 控制台检测
            const element = new Image();
            Object.defineProperty(element, 'id', {
                get: function() {
                    isSuspicious = true;
                    reason = '检测到控制台';
                }
            });
            console.log('%c', element);
`
}

// generateToken 生成验证 token
func (dv *DeviceValidator) generateToken(ip string) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)

	dv.tokensLock.Lock()
	dv.tokens[token] = &tokenData{
		IP:        ip,
		CreatedAt: time.Now(),
		Valid:     true,
	}
	dv.tokensLock.Unlock()

	return token
}

// isValidToken 验证 token 是否有效
func (dv *DeviceValidator) isValidToken(token, ip string) bool {
	dv.tokensLock.RLock()
	defer dv.tokensLock.RUnlock()

	data, exists := dv.tokens[token]
	if !exists {
		return false
	}

	// 检查是否过期
	if time.Since(data.CreatedAt).Seconds() > float64(dv.TokenExpiry) {
		return false
	}

	// 检查 IP 是否匹配 (提取 IP,去除端口)
	tokenIP := strings.Split(data.IP, ":")[0]
	requestIP := strings.Split(ip, ":")[0]

	return data.Valid && tokenIP == requestIP
}

// isExcludedPath 检查路径是否在排除列表中
func (dv *DeviceValidator) isExcludedPath(path string) bool {
	for _, re := range dv.excludeRegex {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// cleanupExpiredTokens 定期清理过期 token
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

// UnmarshalCaddyfile 实现 Caddyfile 配置解析
func (dv *DeviceValidator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "enable":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.Enable = d.Val() == "true"

			case "check_devtools":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.CheckDevTools = d.Val() == "true"

			case "check_fake_mobile":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dv.CheckFakeMobile = d.Val() == "true"

			case "token_expiry":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var err error
				fmt.Sscanf(d.Val(), "%d", &dv.TokenExpiry)
				if err != nil {
					return d.Errf("invalid token_expiry: %v", err)
				}

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

// parseCaddyfile 解析 Caddyfile 指令
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var dv DeviceValidator
	err := dv.UnmarshalCaddyfile(h.Dispenser)
	return &dv, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*DeviceValidator)(nil)
	_ caddyhttp.MiddlewareHandler = (*DeviceValidator)(nil)
	_ caddyfile.Unmarshaler       = (*DeviceValidator)(nil)
)