import type { GuardConfig, GuardRule, RuleSnapshot, RuleTestResult } from '../types'
import request from '../request'

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
function strings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string')
}
function rule(value: unknown): value is GuardRule {
  return record(value) && ['id', 'category', 'description'].every(key => typeof value[key] === 'string')
    && Array.isArray(value.all_groups) && value.all_groups.every(strings)
    && typeof value.max_span_chars === 'number' && typeof value.word_boundaries === 'boolean'
}
function config(value: unknown): value is GuardConfig {
  return record(value) && value.schema_version === 1
    && strings(value.enabled_builtin_ids) && strings(value.disabled_builtin_ids)
    && strings(value.extra_keywords) && strings(value.extra_regexes)
    && Array.isArray(value.custom_rules) && value.custom_rules.every(rule)
}
function snapshot(value: unknown): RuleSnapshot {
  if (!record(value) || !Number.isSafeInteger(value.revision) || typeof value.policy_version !== 'string'
    || !config(value.configuration) || !Array.isArray(value.builtin_rules)
    || !value.builtin_rules.every(item => rule(item) && record(item) && typeof item.enabled === 'boolean' && typeof item.default_enabled === 'boolean')
    || !record(value.counts)) {
    throw new Error('规则数据格式不正确，请检查插件版本')
  }
  return value as unknown as RuleSnapshot
}
export async function getRules(): Promise<RuleSnapshot> {
  return snapshot(await request('api/rules'))
}
export async function saveRules(configuration: GuardConfig, revision: number): Promise<RuleSnapshot> {
  return snapshot(await request('api/rules/save', { expected_revision: revision, configuration }))
}
export async function validateRules(configuration: GuardConfig): Promise<void> {
  const value = await request('api/rules/validate', { configuration })
  if (!record(value) || value.valid !== true)
    throw new Error('规则校验未通过')
}
export async function testRules(configuration: GuardConfig, text: string): Promise<RuleTestResult> {
  const value = await request('api/rules/test', { configuration, text })
  if (!record(value) || typeof value.blocked !== 'boolean' || typeof value.rule_count !== 'number'
    || !(value.matched === null || (record(value.matched) && ['rule_id', 'category', 'policy_version'].every(key => typeof (value.matched as Record<string, unknown>)[key] === 'string')))) {
    throw new Error('规则测试结果格式不正确')
  }
  return value as unknown as RuleTestResult
}
