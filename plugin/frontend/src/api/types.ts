export interface AuditEvent {
  id: string
  timestamp_ms: number
  request_id: string
  client_key_id: string | null
  model: string | null
  transport: string
  rule_id: string | null
  category: string | null
  reason: string
  policy_version: string | null
  context: string | null
  context_truncated: boolean
}

export interface AuditSnapshot {
  events: AuditEvent[]
  retention: {
    capture_context: boolean
    max_events: number
    max_context_chars: number
    retention_days: number
    max_bytes: number
  }
  recording: {
    failures_since_start: number
    last_error_at_ms: number | null
  }
}

export interface PluginHost {
  readonly version: 2
  readonly theme: 'light' | 'dark'
  request: (input: { method: 'GET' | 'POST', path: string, contentType?: string, body?: string }) => Promise<{
    status: number
    contentType: string
    body: ArrayBuffer
  }>
}

export interface GuardRule {
  id: string
  category: string
  description: string
  all_groups: string[][]
  max_span_chars: number
  word_boundaries: boolean
}

export interface GuardConfig {
  schema_version: number
  enabled_builtin_ids: string[]
  disabled_builtin_ids: string[]
  extra_keywords: string[]
  extra_regexes: string[]
  custom_rules: GuardRule[]
}

export interface RuleSnapshot {
  policy_version: string
  revision: number
  configuration: GuardConfig
  builtin_rules: (GuardRule & { default_enabled: boolean, enabled: boolean })[]
  counts: { builtin: number, builtin_enabled: number, keywords: number, regexes: number, custom: number, enabled: number }
}

export interface RuleTestResult {
  blocked: boolean
  matched: { rule_id: string, category: string, policy_version: string } | null
  rule_count: number
}
