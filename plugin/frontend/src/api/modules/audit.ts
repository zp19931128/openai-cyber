import type { AuditEvent, AuditSnapshot } from '../types'
import request from '../request'

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function nullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string'
}

function finiteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

function event(value: unknown): value is AuditEvent {
  return record(value)
    && typeof value.id === 'string'
    && finiteNumber(value.timestamp_ms)
    && typeof value.request_id === 'string'
    && nullableString(value.client_key_id)
    && nullableString(value.model)
    && typeof value.transport === 'string'
    && nullableString(value.rule_id)
    && nullableString(value.category)
    && typeof value.reason === 'string'
    && nullableString(value.policy_version)
    && nullableString(value.context)
    && typeof value.context_truncated === 'boolean'
}

export async function getAudit(): Promise<AuditSnapshot> {
  const value = await request('api/audit')
  if (!record(value) || !Array.isArray(value.events) || value.events.length > 100
    || !value.events.every(event) || !record(value.retention) || !record(value.recording)
    || typeof value.retention.capture_context !== 'boolean'
    || !['max_events', 'max_context_chars', 'retention_days', 'max_bytes'].every(key => finiteNumber(value.retention && (value.retention as Record<string, unknown>)[key]))
    || !finiteNumber(value.recording.failures_since_start)
    || !(value.recording.last_error_at_ms === null || finiteNumber(value.recording.last_error_at_ms))) {
    throw new Error('插件日志格式不正确，请检查插件版本')
  }
  return value as unknown as AuditSnapshot
}
