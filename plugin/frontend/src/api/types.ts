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
  request: (input: { method: 'GET', path: string }) => Promise<{
    status: number
    contentType: string
    body: ArrayBuffer
  }>
}
