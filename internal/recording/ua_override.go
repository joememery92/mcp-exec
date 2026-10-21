package recording

// 反收割 / 反 AI 蜜罐自身防护:给「平台自己发起的
// 抓取」换 UA。
//
// norma 的 WebFetch 工具把请求 UA 写死成 `norma/0.4`(norma tool/webfetch.go 的
// req.Header.Set("user-agent", ...)),配置面(WebFetchConfig / agentcore.Options)
// 没有任何 UA 入口，节点侧也拿不到这个请求——而 `User-Agent: norma/0.4` 对任何
// 一个反 AI 蜜罐就是一个明晃晃的「这里是自动化 agent」信标。平台唯一能碰到这个
// 请求的地方就是自己的记录代理,于是在代理出口按 host 稳定改写:同一目标恒定(UA
// 在任务中途变化本身就是可疑信号),不同目标之间轮换(见 agent.PickUAForHost /
// settings 键 web_ua_pool)。
//
// 只认 norma WebFetch 的确切标记 UA,其余一律不动:浏览器(Playwright,真 Chrome
// UA)、curl(自带 -A 或库 UA)等目标侧可见的指纹保持原样——半吊子换 UA 反而造成
// UA/TLS/JS 指纹失配,那正是 ymh 警告的蜜罐触发器。capture 关时没有记录代理,
// WebFetch 走直连,这条改写不生效（只能靠 MCPNODE_UA 让调用方自带 UA）。

import (
	"strings"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// normaWebFetchUA 是 norma WebFetch 写死的请求 UA(norma tool/webfetch.go:
// req.Header.Set("user-agent", "norma/0.4"))。norma 升级若改动它,这里要跟着改
// ——ua_override_test.go 用同一常量断言改写生效,不会静默失效。
const normaWebFetchUA = "norma/0.4"

// SetUAProvider installs the host→UA resolver used to rewrite the platform's own
// fetch UA("" = leave the request alone). Called once at startup, before Start.
func (t *Traffic) SetUAProvider(fn func(host string) string) {
	if fn == nil {
		t.uaProvider.Store((func(string) string)(nil))
		return
	}
	t.uaProvider.Store(fn)
}

// uaForHost returns the configured UA for host ("" when unwired or blank).
func (t *Traffic) uaForHost(host string) string {
	fn, _ := t.uaProvider.Load().(func(string) string)
	if fn == nil || host == "" {
		return ""
	}
	return strings.TrimSpace(fn(host))
}

// Requestheaders rewrites the UA of the platform's own fetches (norma WebFetch)
// before the proxy forwards them upstream; every other request passes untouched.
// It runs on the live flow, so the recorded request headers carry the UA the
// target actually saw — the original norma marker never reaches the target.
func (s *sink) Requestheaders(f *mproxy.Flow) {
	if f == nil || f.Request == nil || f.Request.URL == nil || f.Request.Header == nil {
		return
	}
	// http.Header.Get is case-insensitive; norma sets the header lowercase.
	if f.Request.Header.Get("User-Agent") != normaWebFetchUA {
		return
	}
	ua := s.t.uaForHost(f.Request.URL.Hostname())
	if ua == "" {
		return
	}
	f.Request.Header.Set("User-Agent", ua)
}
