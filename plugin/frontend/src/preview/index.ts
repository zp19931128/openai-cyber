// @env browser
import type { AuditSnapshot, PluginHost } from '../api/types'
import { applyTheme, createTheme } from '@codex-proxy/ui/theme'

const categories = [
  ['credential_theft', 'cyber.credential_theft', '请求命中凭据窃取组合规则'],
  ['jailbreak', 'jailbreak.override', '请求命中绕过安全限制规则'],
  ['fraud', 'general.fraud', '请求命中诈骗组合规则'],
] as const

function mockSnapshot(empty: boolean): AuditSnapshot {
  return {
    events: empty
      ? []
      : Array.from({ length: 14 }, (_, index) => {
          const [category, rule, reason] = categories[index % categories.length]!
          return {
            id: `preview-${index}`,
            timestamp_ms: Date.now() - index * 180000,
            request_id: `preview-request-${String(1014 - index).padStart(6, '0')}`,
            client_key_id: index === 3 ? null : 'preview-client-key',
            model: index === 3 ? null : 'gpt-preview',
            transport: index % 2 ? 'websocket' : 'http',
            rule_id: rule,
            category,
            reason,
            policy_version: 'preview-policy',
            context: index === 3 ? null : '[user] 这是一条模拟拦截请求，仅用于检查日志详情与长文本布局\n\n[user] 本次请求携带的文本将在此展示，常见密钥已处理为 [REDACTED]\n\n[user] <script>alert("此内容只作为文本显示")</script>',
            context_truncated: index === 1,
          }
        }),
    retention: { capture_context: true, max_events: 100, max_context_chars: 4000, retention_days: 7, max_bytes: 196608 },
    recording: { failures_since_start: 0, last_error_at_ms: null },
  }
}

export function installPreviewHost(): boolean {
  if (!import.meta.env.DEV || window.codexProxyPlugin)
    return false

  const parameters = new URLSearchParams(window.location.search)
  const mode = parameters.get('preview')
  const theme = parameters.get('theme') === 'dark' ? 'dark' : 'light'
  applyTheme(document.documentElement, createTheme({ scheme: theme }))

  const host: PluginHost = {
    version: 2,
    theme,
    request: async () => {
      await new Promise(resolve => window.setTimeout(resolve, mode === 'loading' ? 30000 : 160))
      const body = mode === 'error'
        ? { error: { code: 'state_unavailable', message: '无法读取日志存储，请稍后重试' } }
        : mockSnapshot(mode === 'empty')
      const bytes = new TextEncoder().encode(JSON.stringify(body))
      return { status: mode === 'error' ? 503 : 200, contentType: 'application/json', body: bytes.buffer }
    },
  }
  Object.defineProperty(window, 'codexProxyPlugin', { configurable: true, value: host })
  return true
}
