// @env browser
import type { AuditSnapshot, GuardConfig, PluginHost, RuleSnapshot } from '../api/types'
import { applyTheme, createTheme } from '@codex-proxy/ui/theme'
import builtin from '../../../../rules/builtin.json'

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

  let configuration: GuardConfig = { schema_version: 1, enabled_builtin_ids: [], disabled_builtin_ids: [], extra_keywords: ['模拟拒绝短语'], extra_regexes: [], custom_rules: [] }
  let revision = 12
  function catalog(config = configuration): RuleSnapshot {
    const builtinRules = builtin.rules.map((rule) => {
      const defaultEnabled = !builtin.default_disabled_ids.includes(rule.id)
      return { ...rule, default_enabled: defaultEnabled, enabled: (defaultEnabled || config.enabled_builtin_ids.includes(rule.id)) && !config.disabled_builtin_ids.includes(rule.id) }
    })
    return { policy_version: builtin.policy_version, revision, configuration: JSON.parse(JSON.stringify(config)), builtin_rules: builtinRules, counts: { builtin: builtinRules.length, builtin_enabled: builtinRules.filter(rule => rule.enabled).length, keywords: config.extra_keywords.length, regexes: config.extra_regexes.length, custom: config.custom_rules.length, enabled: builtinRules.filter(rule => rule.enabled).length + config.extra_keywords.length + config.extra_regexes.length + config.custom_rules.length } }
  }
  const host: PluginHost = {
    version: 2,
    theme,
    request: async (input) => {
      await new Promise(resolve => window.setTimeout(resolve, mode === 'loading' ? 30000 : 160))
      let status = 200
      let body: unknown
      if (mode === 'error') {
        status = 503
        body = { error: { code: 'unavailable', message: '模拟服务暂时不可用，请稍后重试' } }
      }
      else if (input.path === 'api/audit') {
        body = mockSnapshot(mode === 'empty')
      }
      else if (input.path === 'api/rules') {
        body = catalog()
      }
      else {
        const data = JSON.parse(input.body ?? '{}') as { configuration: GuardConfig, text?: string, expected_revision?: number }
        let invalid = ''
        if (data.configuration.enabled_builtin_ids.some(id => data.configuration.disabled_builtin_ids.includes(id)))
          invalid = '同一内置规则不能同时启用和停用'
        for (const pattern of data.configuration.extra_regexes) {
          try {
            const regex = new RegExp(pattern)
            if (regex.test(''))
              invalid = '正则不能匹配空文本'
          }
          catch { invalid = '无效正则表达式' }
        }
        if (invalid) {
          status = 422
          body = { error: { code: 'invalid_configuration', message: '规则配置无效', details: invalid } }
        }
        else if (input.path === 'api/rules/save') {
          if (mode === 'conflict' || data.expected_revision !== revision) {
            status = 409
            body = { error: { code: 'conflict', message: '插件配置已变化，请重新加载后再保存' } }
          }
          else {
            configuration = data.configuration
            revision++
            body = catalog()
          }
        }
        else if (input.path === 'api/rules/test') {
          const index = data.configuration.extra_keywords.findIndex(phrase => data.text?.includes(phrase))
          body = { blocked: index >= 0, matched: index >= 0 ? { rule_id: `custom.keyword.${index + 1}`, category: 'custom_keyword', policy_version: builtin.policy_version } : null, rule_count: catalog(data.configuration).counts.enabled, policy_version: builtin.policy_version }
        }
        else {
          body = { valid: true, rule_count: catalog(data.configuration).counts.enabled, policy_version: builtin.policy_version }
        }
      }
      const bytes = new TextEncoder().encode(JSON.stringify(body))
      return { status, contentType: 'application/json', body: bytes.buffer }
    },
  }
  Object.defineProperty(window, 'codexProxyPlugin', { configurable: true, value: host })
  return true
}
