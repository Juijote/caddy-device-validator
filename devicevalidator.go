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
	// 配置项
	Enable            bool     `json:"enable,omitempty"`
	CheckDevTools     bool     `json:"check_devtools,omitempty"`
	CheckFakeMobile   bool     `json:"check_fake_mobile,omitempty"`
	CheckHeadless     bool     `json:"check_headless,omitempty"`      // 检测无头浏览器
	ForceVerification bool     `json:"force_verification,omitempty"`  // 强制所有请求先验证
	DebugMode         bool     `json:"debug_mode,omitempty"`          // 调试模式,显示检测详情
	TokenExpiry       int      `json:"token_expiry,omitempty"`        // 秒
	ExcludePaths      []string `json:"exclude_paths,omitempty"`
	CustomMessage     string   `json:"custom_message,omitempty"`

	// 运行时数据
	tokens     map[string]*tokenData
	tokensLock sync.RWMutex
	logger     *zap.Logger

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
	dv.logger = ctx.Logger()
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

	// 如果开启强制验证模式,所有请求都需要验证
	if dv.ForceVerification {
		cookie, err := r.Cookie("device_verified")
		if err != nil || cookie.Value != "1" {
			dv.logger.Info("force verification mode",
				zap.String("path", r.URL.Path))
			dv.serveValidationPage(w, r)
			return nil
		}
	}

	// 检查设备是否可疑
	if dv.isSuspiciousDevice(r) {
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

	// 检查是否已经通过验证
	verifiedCookie, hasVerified := r.Cookie("device_verified")
	if hasVerified == nil && verifiedCookie.Value == "1" {
		// 已经验证过,直接放行
		return false
	}

	// 检查是否为无头浏览器特征(优先级最高)
	if dv.CheckHeadless {
		// HeadlessChrome UA 检测
		if strings.Contains(userAgent, "HeadlessChrome") {
			dv.logger.Info("detected HeadlessChrome UA",
				zap.String("ua", userAgent))
			return true
		}

		// PhantomJS UA 检测
		if strings.Contains(userAgent, "PhantomJS") || strings.Contains(userAgent, "Phantom") {
			dv.logger.Info("detected PhantomJS UA",
				zap.String("ua", userAgent))
			return true
		}
	}

	// 如果是移动设备 UA 且开启了伪造检测,需要 JS 验证
	if dv.CheckFakeMobile && isMobileUA {
		dv.logger.Info("mobile UA detected, need verification",
			zap.String("ua", userAgent))
		return true
	}

	// 如果开启了 DevTools 检测(非移动设备),需要 JS 验证
	if dv.CheckDevTools && !isMobileUA {
		dv.logger.Info("devtools check enabled, need verification",
			zap.String("ua", userAgent))
		return true
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
        .debug { 
            margin-top: 20px; 
            padding: 10px; 
            background: #f5f5f5; 
            border-radius: 5px;
            font-size: 12px;
            color: #666;
            text-align: left;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔍</div>
        <h2>正在验证设备</h2>
        <div class="spinner"></div>
        <p class="loading">请稍候...</p>
        <div class="debug" id="debug"></div>
    </div>
    
    <script>
        (function() {
            const checks = {};
            let isSuspicious = false;
            let reasons = [];
            
            // 收集设备信息
            const deviceInfo = {
                screenWidth: window.screen.width,
                screenHeight: window.screen.height,
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight,
                outerWidth: window.outerWidth,
                outerHeight: window.outerHeight,
                availWidth: window.screen.availWidth,
                availHeight: window.screen.availHeight,
                hasTouch: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
                maxTouchPoints: navigator.maxTouchPoints || 0,
                devicePixelRatio: window.devicePixelRatio,
                platform: navigator.platform,
                userAgent: navigator.userAgent
            };
            
            // === 1. DevTools 检测(只在真正打开时才触发) ===
            %s
            
            // === 2. 伪造移动设备检测 ===
            %s
            
            // === 3. 无头浏览器检测 ===
            %s
            
            // 显示调试信息
            %s
            
            if (isSuspicious) {
                document.querySelector('.container').innerHTML = 
                    '<div class="icon">⛔</div>' +
                    '<h2 class="denied">访问被拒绝</h2>' +
                    '<p class="denied">%s</p>' +
                    '<p style="color: #999; font-size: 12px; margin-top: 20px;">原因: ' + reasons.join(', ') + '</p>';
            } else {
                // 设置 cookie 并重定向
                document.cookie = 'screen_width=' + deviceInfo.screenWidth + '; path=/; max-age=300; SameSite=Lax';
                document.cookie = 'device_verified=1; path=/; max-age=300; SameSite=Lax';
                
                const url = new URL(window.location.href);
                url.searchParams.set('_vt', '%s');
                
                setTimeout(() => {
                    window.location.href = url.toString();
                }, 500);
            }
        })();
    </script>
</body>
</html>`, 
		dv.getDevToolsDetectionJS(), 
		dv.getFakeMobileDetectionJS(),
		dv.getHeadlessDetectionJS(),
		message, 
		token)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// getDevToolsDetectionJS 返回 DevTools 检测 JS 代码(只在真正打开时触发)
func (dv *DeviceValidator) getDevToolsDetectionJS() string {
	if !dv.CheckDevTools {
		return "// DevTools detection disabled"
	}

	return `
            // 只在 DevTools 真正打开并可见时才检测
            // 使用更严格的阈值,避免误判
            const threshold = 200;  // 提高阈值到 200px
            const widthDiff = deviceInfo.outerWidth - deviceInfo.innerWidth;
            const heightDiff = deviceInfo.outerHeight - deviceInfo.innerHeight;
            
            // 只有当差异非常明显时才认为是 DevTools
            // 正常浏览器的工具栏/滚动条差异一般不超过 100px
            if (widthDiff > threshold || heightDiff > threshold) {
                // 二次确认:检查是否真的是 DevTools 导致的
                const isVerticalDevTools = heightDiff > threshold;
                const isHorizontalDevTools = widthDiff > threshold;
                
                // DevTools 打开时,差异会非常明显(通常 > 300px)
                if (widthDiff > 300 || heightDiff > 300) {
                    isSuspicious = true;
                    reasons.push('开发者工具已打开 (尺寸差: ' + Math.max(widthDiff, heightDiff) + 'px)');
                }
            }
`
}

// getFakeMobileDetectionJS 返回伪造移动设备检测 JS 代码
func (dv *DeviceValidator) getFakeMobileDetectionJS() string {
	if !dv.CheckFakeMobile {
		return "// Fake mobile detection disabled"
	}

	return `
            const isMobileUA = /Mobile|Android|iPhone|iPad/i.test(deviceInfo.userAgent);
            
            if (isMobileUA) {
                let fakeScore = 0;  // 可疑分数,累积判断
                
                // 1. 检查触摸支持(最重要的指标)
                if (!deviceInfo.hasTouch || deviceInfo.maxTouchPoints === 0) {
                    fakeScore += 3;
                    console.log('No touch support detected');
                }
                
                // 2. 检查屏幕尺寸(真实手机一般 < 768px)
                if (deviceInfo.screenWidth > 768) {
                    fakeScore += 2;
                    console.log('Large screen detected:', deviceInfo.screenWidth);
                }
                
                // 3. 检查设备像素比(真实手机一般 >= 2)
                if (deviceInfo.devicePixelRatio < 1.5 && deviceInfo.screenWidth < 768) {
                    fakeScore += 1;
                    console.log('Low DPR for mobile:', deviceInfo.devicePixelRatio);
                }
                
                // 4. 检查平台信息
                const platform = deviceInfo.platform.toLowerCase();
                if (platform.includes('win') || platform.includes('mac') || platform.includes('linux')) {
                    fakeScore += 2;
                    console.log('Desktop platform:', platform);
                }
                
                // 综合判断:分数 >= 4 认为是伪造的
                if (fakeScore >= 4) {
                    isSuspicious = true;
                    reasons.push('伪造的移动设备 (可疑分数: ' + fakeScore + ')');
                }
                
                console.log('Fake mobile score:', fakeScore);
            }
`
}

// getHeadlessDetectionJS 返回无头浏览器检测 JS 代码
func (dv *DeviceValidator) getHeadlessDetectionJS() string {
	if !dv.CheckHeadless {
		return "// Headless browser detection disabled"
	}

	return `
            // 无头浏览器检测使用评分机制,避免误判
            let headlessScore = 0;
            // 1. WebDriver 检测(权重最高)
            if (navigator.webdriver === true) {
                headlessScore += 3;
                reasons.push('检测到 WebDriver');
            }
            
            // 2. Chrome 特征检测
            if (typeof window.chrome === 'undefined' && /Chrome/.test(navigator.userAgent)) {
                headlessScore += 2;
            }
            
            // 3. Plugins 类型检测
            if (navigator.plugins && !(navigator.plugins instanceof PluginArray)) {
                headlessScore += 2;
            }
            
            // 4. 语言检测
            if (!navigator.languages || navigator.languages.length === 0) {
                headlessScore += 1;
            }
            
            // 5. Phantom 特征检测
            if (window.callPhantom || window._phantom || window.phantom) {
                headlessScore += 3;
                reasons.push('检测到 PhantomJS');
            }
            
            // 6. Selenium 特征检测
            if (window._Selenium_IDE_Recorder || window.callSelenium || window._selenium ||
                document.__webdriver_script_fn || document.__selenium_unwrapped) {
                headlessScore += 3;
                reasons.push('检测到 Selenium');
            }
            
            // 7. Nightmare 特征检测
            if (window.__nightmare) {
                headlessScore += 3;
                reasons.push('检测到 Nightmare');
            }
            
            // 只有累积分数 >= 3 才判定为无头浏览器
            if (headlessScore >= 3) {
                isSuspicious = true;
                reasons.push('疑似无头浏览器 (分数: ' + headlessScore + ')');
            }
            
            console.log('Headless score:', headlessScore);
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

	if time.Since(data.CreatedAt).Seconds() > float64(dv.TokenExpiry) {
		return false
	}

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

// getDebugJS 返回调试 JS 代码
func (dv *DeviceValidator) getDebugJS() string {
	if !dv.DebugMode {
		return ""
	}

	return `
            document.getElementById('debug').style.display = 'block';
            document.getElementById('debug').innerHTML = '<strong>检测详情:</strong><pre>' + 
                JSON.stringify({
                    isSuspicious: isSuspicious,
                    reasons: reasons,
                    deviceInfo: deviceInfo
                }, null, 2) + '</pre>';
`
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