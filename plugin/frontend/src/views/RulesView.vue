<script setup lang="ts">
import type { GuardConfig, GuardRule, RuleSnapshot, RuleTestResult } from '../api/types'
import { ZButton, ZDialog, ZFormItem, ZInput, ZInputNumber, ZSelect, ZSwitch, ZTextarea } from '@codex-proxy/ui'
import { ChevronDown, Plus, RefreshCw, Save, Search } from '@lucide/vue'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { getRules, saveRules, testRules, validateRules } from '../api/modules/rules'
import { PluginRequestError } from '../api/request'

interface Row {
  key: string
  id: string
  description: string
  category: string
  source: 'builtin' | 'keyword' | 'regex' | 'custom'
  index: number
  enabled: boolean
  pattern?: string
  rule?: GuardRule
}
const snapshot = ref<RuleSnapshot | null>(null)
const draft = ref<GuardConfig | null>(null)
const loading = ref(false)
const saving = ref(false)
const saved = ref(false)
const reloadRequired = ref(false)
const error = ref('')
const notice = ref('')
const search = ref('')
const source = ref('')
const status = ref('')
const category = ref('')
const page = ref(1)
const editor = ref(false)
const editing = ref<Row | null>(null)
const kind = ref('keyword')
const phrase = ref('')
const ruleId = ref('')
const description = ref('')
const ruleCategory = ref('custom')
const groups = ref(['', ''])
const span = ref(160)
const boundaries = ref(false)
const editorError = ref('')
const checking = ref(false)
const removing = ref<Row | null>(null)
const removeOpen = computed({ get: () => removing.value !== null, set: (open: boolean) => {
  if (!open)
    removing.value = null
} })
const reloadConfirm = ref(false)
const testText = ref('')
const testing = ref(false)
const testError = ref('')
const testResult = ref<RuleTestResult | null>(null)
const categoryNames: Record<string, string> = {
  account_takeover: '盗号',
  child_sexual_exploitation: '未成年人性剥削',
  credential_theft: '凭据窃取',
  dangerous_substances: '危险物质',
  denial_of_service: '拒绝服务攻击',
  fraud: '诈骗',
  illegal_weapons: '非法武器',
  jailbreak: '安全限制绕过',
  malicious_evasion: '恶意规避检测',
  malicious_exfiltration: '恶意数据外传',
  malicious_persistence: '恶意持久化',
  phishing: '钓鱼',
  privacy_abuse: '隐私滥用',
  ransomware: '勒索软件',
  unauthorized_access: '未授权访问',
  violent_harm: '暴力伤害',
  custom_keyword: '补充关键词',
  custom_regex: '补充正则',
  custom: '自定义',
}
const sourceNames = { builtin: '内置规则', keyword: '关键词', regex: '正则', custom: '组合规则' }
const dirty = computed(() => !!draft.value && JSON.stringify(draft.value) !== JSON.stringify(snapshot.value?.configuration))
const locked = computed(() => saving.value || saved.value || checking.value || loading.value)
const editLocked = computed(() => locked.value || reloadRequired.value)
const rows = computed<Row[]>(() => {
  if (!snapshot.value || !draft.value)
    return []
  return [
    ...snapshot.value.builtin_rules.map((rule, index) => ({ key: `builtin:${rule.id}`, id: rule.id, description: rule.description, category: rule.category, source: 'builtin' as const, index, enabled: !draft.value!.disabled_builtin_ids.includes(rule.id), rule })),
    ...draft.value.extra_keywords.map((pattern, index) => ({ key: `keyword:${index}`, id: `custom.keyword.${index + 1}`, description: pattern, category: 'custom_keyword', source: 'keyword' as const, index, enabled: true, pattern })),
    ...draft.value.extra_regexes.map((pattern, index) => ({ key: `regex:${index}`, id: `custom.regex.${index + 1}`, description: pattern, category: 'custom_regex', source: 'regex' as const, index, enabled: true, pattern })),
    ...draft.value.custom_rules.map((rule, index) => ({ key: `custom:${rule.id}`, id: rule.id, description: rule.description, category: rule.category, source: 'custom' as const, index, enabled: true, rule })),
  ]
})
const enabled = computed(() => rows.value.filter(row => row.enabled).length)
const filtered = computed(() => {
  const term = search.value.trim().toLocaleLowerCase()
  return rows.value.filter(row => (!source.value || row.source === source.value)
    && (!status.value || row.enabled === (status.value === 'enabled')) && (!category.value || row.category === category.value)
    && (!term || JSON.stringify([row.id, row.description, row.category, row.pattern, row.rule?.all_groups]).toLocaleLowerCase().includes(term)))
})
const categoryOptions = computed(() => [{ label: '全部类别', value: '' }, ...[...new Set(rows.value.map(row => row.category))].sort().map(value => ({ value, label: categoryNames[value] ?? value }))])
const pageCount = computed(() => Math.max(1, Math.ceil(filtered.value.length / 10)))
const visible = computed(() => filtered.value.slice((page.value - 1) * 10, page.value * 10))
watch([search, source, status, category], () => {
  page.value = 1
})
watch(pageCount, (count) => {
  page.value = Math.min(page.value, count)
})
watch([draft, testText], () => {
  testResult.value = null
  testError.value = ''
  notice.value = ''
}, { deep: true, flush: 'sync' })
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}
function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : '操作失败，请重试'
}
async function load() {
  if (loading.value || locked.value)
    return
  loading.value = true
  error.value = ''
  try {
    snapshot.value = await getRules()
    draft.value = clone(snapshot.value.configuration)
    editor.value = false
    reloadRequired.value = false
  }
  catch (cause) { error.value = message(cause) }
  finally { loading.value = false }
}
function requestReload() {
  if (editor.value)
    return
  if (dirty.value)
    reloadConfirm.value = true
  else void load()
}
function toggle(row: Row, value: boolean) {
  if (!draft.value || editLocked.value)
    return
  draft.value.disabled_builtin_ids = value
    ? draft.value.disabled_builtin_ids.filter(id => id !== row.id)
    : [...new Set([...draft.value.disabled_builtin_ids, row.id])]
}
function openEditor(row?: Row) {
  if (editLocked.value)
    return
  editing.value = row ?? null
  kind.value = row?.source ?? 'keyword'
  phrase.value = row?.pattern ?? ''
  ruleId.value = row?.rule?.id ?? `custom.rule.${Date.now()}`
  description.value = row?.rule?.description ?? ''
  ruleCategory.value = row?.rule?.category ?? 'custom'
  groups.value = row?.rule?.all_groups.map(group => group.join('\n')) ?? ['', '']
  span.value = row?.rule?.max_span_chars ?? 160
  boundaries.value = row?.rule?.word_boundaries ?? false
  editorError.value = ''
  editor.value = true
}
function example() {
  if (kind.value === 'keyword') {
    phrase.value = '我自己指定的拒绝短语'
  }
  else if (kind.value === 'regex') {
    phrase.value = 'blocked\\s+phrase'
  }
  else {
    description.value = '同时出现两个条件才拦截'
    groups.value = ['条件一\n条件一的替代短语', '条件二']
  }
}
async function applyEditor() {
  if (!draft.value || editLocked.value)
    return
  editorError.value = ''
  const next = clone(draft.value)
  const index = editing.value?.index
  if (kind.value === 'custom') {
    const rule: GuardRule = { id: ruleId.value.trim(), category: ruleCategory.value.trim(), description: description.value.trim(), all_groups: groups.value.map(group => group.split('\n').map(term => term.trim()).filter(Boolean)), max_span_chars: span.value, word_boundaries: boundaries.value }
    if (!rule.id || !rule.category || !rule.description || !rule.all_groups.length || rule.all_groups.some(group => !group.length)) {
      editorError.value = '请填写名称、规则 ID、类别及每个条件组'
      return
    }
    if (index === undefined)
      next.custom_rules.push(rule)
    else next.custom_rules[index] = rule
  }
  else {
    const value = kind.value === 'regex' ? phrase.value : phrase.value.trim()
    if (!value.trim()) {
      editorError.value = '请填写要拦截的短语或正则'
      return
    }
    const list = kind.value === 'keyword' ? next.extra_keywords : next.extra_regexes
    if (index === undefined)
      list.push(value)
    else list[index] = value
  }
  checking.value = true
  try {
    await validateRules(next)
    draft.value = next
    editor.value = false
    notice.value = '已加入待保存修改，点击“保存并生效”后启用'
  }
  catch (cause) { editorError.value = message(cause) }
  finally { checking.value = false }
}
function remove() {
  if (!draft.value || !removing.value || editLocked.value)
    return
  const row = removing.value
  if (row.source === 'keyword')
    draft.value.extra_keywords.splice(row.index, 1)
  if (row.source === 'regex')
    draft.value.extra_regexes.splice(row.index, 1)
  if (row.source === 'custom')
    draft.value.custom_rules.splice(row.index, 1)
  removing.value = null
}
async function save() {
  if (!draft.value || !snapshot.value || !dirty.value || editLocked.value)
    return
  saving.value = true
  error.value = ''
  try {
    snapshot.value = await saveRules(clone(draft.value), snapshot.value.revision)
    draft.value = clone(snapshot.value.configuration)
    saved.value = true
    editor.value = false
  }
  catch (cause) {
    error.value = message(cause)
    reloadRequired.value = !(cause instanceof PluginRequestError && [400, 422].includes(cause.status))
  }
  finally { saving.value = false }
}
async function runTest() {
  if (!draft.value || testing.value || locked.value)
    return
  testing.value = true
  testError.value = ''
  testResult.value = null
  const testedConfig = JSON.stringify(draft.value)
  const testedText = testText.value
  try {
    const result = await testRules(clone(draft.value), testedText)
    if (testedConfig === JSON.stringify(draft.value) && testedText === testText.value)
      testResult.value = result
  }
  catch (cause) {
    if (testedConfig === JSON.stringify(draft.value) && testedText === testText.value)
      testError.value = message(cause)
  }
  finally { testing.value = false }
}
function beforeUnload(event: BeforeUnloadEvent) {
  if (dirty.value || editor.value) {
    event.preventDefault()
    event.returnValue = ''
  }
}
onMounted(() => {
  void load()
  window.addEventListener('beforeunload', beforeUnload)
})
onBeforeUnmount(() => window.removeEventListener('beforeunload', beforeUnload))
</script>

<template>
  <section class="grid min-w-0 gap-4" aria-label="规则管理">
    <div v-if="saved" class="rounded-z bg-z-success-container px-3 py-3 text-z-success-on-container" role="status">
      规则已保存并发布，请刷新整个 CPR 页面或重新打开插件页面后继续操作
    </div>
    <div v-if="error" class="break-words rounded-z bg-z-error-container px-3 py-2 text-z-error-on-container" role="alert">
      {{ error }}
    </div>
    <p v-if="reloadRequired" class="text-z-xs text-z-warning-text" role="status">
      请先重新加载并核对已保存配置，再继续修改，无法重新加载时请刷新整个 CPR 页面
    </p>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span class="font-emphasis">共 {{ rows.length }} 条 · 启用 {{ enabled }} 条 · 停用 {{ rows.length - enabled }} 条</span>
        <span v-if="snapshot" class="text-z-xs text-z-text-secondary">内置 {{ snapshot.builtin_rules.length }} 条 · 自定义 {{ rows.length - snapshot.builtin_rules.length }} 条</span>
        <span v-if="dirty" class="text-z-xs font-emphasis text-z-warning-text">有未保存修改，离开页面会丢失</span>
      </div>
      <div class="flex flex-wrap gap-2">
        <ZButton :loading="loading" :disabled="locked || editor" @click="requestReload">
          <RefreshCw class="size-4" aria-hidden="true" />重新加载
        </ZButton>
        <ZButton :disabled="!draft || editLocked || editor" @click="openEditor()">
          <Plus class="size-4" aria-hidden="true" />新增规则
        </ZButton>
        <ZButton type="primary" :loading="saving" :disabled="!dirty || editLocked || editor" @click="save">
          <Save class="size-4" aria-hidden="true" />保存并生效
        </ZButton>
      </div>
    </div>
    <p v-if="notice" class="text-z-xs text-z-primary-text" role="status">
      {{ notice }}
    </p>
    <p v-if="snapshot" class="text-z-xs text-z-text-secondary">
      词库 {{ snapshot.policy_version }} · 配置版本 {{ snapshot.revision }}<span v-if="dirty"> · 下方显示待保存规则</span>
    </p>

    <form v-if="editor" class="grid min-w-0 gap-4 rounded-z-card bg-z-bg-container p-4 shadow-z-card" aria-label="规则编辑表单" @submit.prevent="applyEditor">
      <div class="flex items-center justify-between gap-3">
        <span class="font-emphasis">{{ editing ? '编辑规则' : '新增规则' }}</span><ZButton size="small" :disabled="checking" @click="editor = false">
          取消
        </ZButton>
      </div>
      <ZFormItem for="rule-kind" label="规则类型">
        <ZSelect id="rule-kind" v-model="kind" aria-label="规则类型" :disabled="!!editing || checking" :options="[{ label: '关键词 · 包含指定短语就拦截', value: 'keyword' }, { label: '组合规则 · 多组条件同时命中', value: 'custom' }, { label: '正则 · 高级匹配', value: 'regex' }]" />
      </ZFormItem>
      <div v-if="kind !== 'custom'" class="grid gap-2">
        <ZFormItem for="rule-pattern" :label="kind === 'keyword' ? '拦截短语' : '正则表达式'">
          <ZTextarea id="rule-pattern" v-model="phrase" :rows="2" :disabled="checking" :placeholder="kind === 'keyword' ? '填写一条明确的短语' : '例如 blocked\\s+phrase'" />
        </ZFormItem>
        <p class="text-z-xs text-z-text-secondary">
          {{ kind === 'keyword' ? '包含这条短语就会拦截，避免仅填写“扫描”等常用单词' : '使用 Rust regex 语法，不支持环视和反向引用，在规范化后的单句上匹配' }}
        </p>
      </div>
      <template v-else>
        <ZFormItem for="rule-description" label="规则名称">
          <ZInput id="rule-description" v-model="description" aria-label="规则名称" :disabled="checking" placeholder="例如 同时出现两个指定条件" />
        </ZFormItem>
        <div class="grid gap-3 sm:grid-cols-2">
          <ZFormItem for="rule-id" label="规则 ID">
            <ZInput id="rule-id" v-model="ruleId" aria-label="规则 ID" :disabled="checking" />
          </ZFormItem>
          <ZFormItem for="rule-category" label="类别">
            <ZInput id="rule-category" v-model="ruleCategory" aria-label="规则类别" :disabled="checking" placeholder="例如 custom" />
          </ZFormItem>
        </div>
        <p class="text-z-xs text-z-text-secondary">
          所有条件组都需命中，每组任选一个短语，同句且在指定距离内才拦截
        </p>
        <div v-for="(_, index) in groups" :key="index" class="grid gap-2">
          <div class="flex items-center justify-between">
            <span class="text-z-xs font-emphasis">条件组 {{ index + 1 }} · 每行一个备选短语</span><ZButton size="small" :disabled="groups.length <= 1 || checking" @click="groups.splice(index, 1)">
              移除组
            </ZButton>
          </div>
          <ZTextarea :id="`group-${index}`" v-model="groups[index]" :aria-label="`条件组 ${index + 1}`" :rows="2" :disabled="checking" placeholder="短语一&#10;同义短语" />
        </div>
        <ZButton class="w-fit" :disabled="groups.length >= 16 || checking" @click="groups.push('')">
          添加条件组
        </ZButton>
        <div class="flex flex-wrap items-end gap-4">
          <ZFormItem for="rule-span" label="最大匹配距离（字符）">
            <ZInputNumber id="rule-span" v-model="span" aria-label="最大匹配距离" :min="1" :max="4096" :precision="0" :disabled="checking" />
          </ZFormItem>
          <ZSwitch v-model="boundaries" label="检查英文单词边界" :disabled="checking" />
        </div>
      </template>
      <div v-if="editorError" class="break-words rounded-z bg-z-error-container px-3 py-2 text-z-error-on-container" role="alert">
        {{ editorError }}
      </div>
      <div class="flex flex-wrap justify-between gap-2">
        <ZButton :disabled="!!editing || checking" @click="example">
          填入示例
        </ZButton><ZButton type="primary" native-type="submit" :loading="checking">
          校验并加入待保存
        </ZButton>
      </div>
    </form>

    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <ZInput v-model="search" aria-label="搜索规则" placeholder="搜索名称、ID 或短语" :disabled="!draft">
        <template #prefix>
          <Search class="size-4" aria-hidden="true" />
        </template>
      </ZInput>
      <ZSelect v-model="source" aria-label="规则来源" :disabled="!draft" :options="[{ label: '全部来源', value: '' }, ...Object.entries(sourceNames).map(([value, label]) => ({ label, value }))]" />
      <ZSelect v-model="status" aria-label="启用状态" :disabled="!draft" :options="[{ label: '全部状态', value: '' }, { label: '已启用', value: 'enabled' }, { label: '已停用', value: 'disabled' }]" />
      <ZSelect v-model="category" aria-label="规则类别筛选" :disabled="!draft" :options="categoryOptions" />
    </div>
    <div v-if="loading && !snapshot" class="py-10 text-center text-z-text-secondary" role="status">
      正在读取规则
    </div>
    <div v-else-if="!snapshot" class="py-10 text-center text-z-text-secondary">
      暂时无法显示规则，请重新加载
    </div>
    <div v-else-if="!filtered.length" class="py-10 text-center text-z-text-secondary">
      没有符合条件的规则
    </div>
    <div v-else class="grid min-w-0 gap-2">
      <article v-for="row in visible" :key="row.key" class="grid min-w-0 gap-2 rounded-z-card bg-z-bg-container px-4 py-3 shadow-z-card">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div class="min-w-0 flex-1 basis-56">
            <p class="break-words font-emphasis">
              {{ row.description }}
            </p><p class="mt-1 break-all font-mono text-z-xs text-z-text-secondary">
              {{ row.id }}
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-3 text-z-xs">
            <span class="text-z-text-secondary">{{ sourceNames[row.source] }} · {{ categoryNames[row.category] ?? row.category }}</span><ZSwitch v-if="row.source === 'builtin'" :model-value="row.enabled" :label="row.enabled ? '已启用' : '已停用'" :aria-label="`${row.enabled ? '停用' : '启用'} ${row.id}`" :disabled="editLocked || editor" @update:model-value="toggle(row, $event)" /><span v-else class="text-z-success-text">已启用</span>
          </div>
        </div>
        <details class="group min-w-0 text-z-xs">
          <summary class="flex w-fit cursor-pointer items-center gap-1 rounded-z py-1 text-z-text-secondary focus-visible:outline-2 focus-visible:outline-z-primary">
            查看匹配条件<ChevronDown class="size-3.5 transition-transform group-open:rotate-180" aria-hidden="true" />
          </summary>
          <div v-if="row.rule" class="grid min-w-0 gap-2 pt-2">
            <p v-for="(group, index) in row.rule.all_groups" :key="index" class="break-words rounded-z bg-z-fill-quaternary px-3 py-2">
              <span class="font-emphasis">条件组 {{ index + 1 }}：</span>{{ group.join(' / ') }}
            </p><p class="text-z-text-secondary">
              每组任选一个短语，所有组同时满足 · 同句 {{ row.rule.max_span_chars }} 字符内 · 英文单词边界{{ row.rule.word_boundaries ? '开启' : '关闭' }}
            </p>
          </div>
          <p v-else class="whitespace-pre-wrap break-all rounded-z bg-z-fill-quaternary px-3 py-2">
            {{ row.source === 'keyword' ? '包含即拦截：' : '正则匹配：' }}{{ row.pattern }}
          </p>
        </details>
        <div v-if="row.source !== 'builtin'" class="flex justify-end gap-2">
          <ZButton size="small" :disabled="editLocked || editor" @click="openEditor(row)">
            编辑
          </ZButton><ZButton size="small" :disabled="editLocked || editor" @click="removing = row">
            删除
          </ZButton>
        </div>
      </article>
    </div>
    <div v-if="snapshot" class="flex flex-wrap items-center justify-between gap-3 text-z-xs text-z-text-secondary">
      <span>筛选后 {{ filtered.length }} 条 · 第 {{ page }} / {{ pageCount }} 页</span><div class="flex gap-2">
        <ZButton size="small" :disabled="page === 1" @click="page--">
          上一页
        </ZButton><ZButton size="small" :disabled="page === pageCount" @click="page++">
          下一页
        </ZButton>
      </div>
    </div>

    <details v-if="draft" class="group rounded-z-card bg-z-bg-container p-4 shadow-z-card">
      <summary class="w-fit cursor-pointer font-emphasis focus-visible:outline-2 focus-visible:outline-z-primary">
        测试当前规则
      </summary>
      <div class="grid gap-3 pt-3">
        <p class="text-z-xs text-z-text-secondary">
          按当前待保存配置测试，只检查输入文本，不调用模型，也不写拦截日志
        </p><ZTextarea v-model="testText" aria-label="规则测试文本" :rows="3" :disabled="locked || testing" placeholder="输入一段文本，检查是否会被当前规则拦截" /><ZButton class="w-fit" :loading="testing" :disabled="!testText.trim() || locked || editor" @click="runTest">
          运行测试
        </ZButton><p v-if="testError" class="break-words text-z-error-text" role="alert">
          {{ testError }}
        </p><div v-if="testResult" class="break-words rounded-z px-3 py-2 text-z-xs" :class="testResult.blocked ? 'bg-z-error-container text-z-error-on-container' : 'bg-z-success-container text-z-success-on-container'" role="status">
          {{ testResult.blocked ? `会拦截 · ${testResult.matched?.rule_id} · ${categoryNames[testResult.matched?.category ?? ''] ?? testResult.matched?.category}` : '未命中词库，不代表符合全部 OpenAI 政策' }}
        </div>
      </div>
    </details>
    <ZDialog v-model="removeOpen" title="删除这条补充规则？" :draggable="false">
      <p class="break-words">
        {{ removing?.description }}
      </p><p class="mt-2 text-z-xs text-z-text-secondary">
        删除后仍需点击“保存并生效”，内置规则不会受影响
      </p><template #footer>
        <ZButton @click="removing = null">
          取消
        </ZButton><ZButton type="primary" @click="remove">
          确认删除
        </ZButton>
      </template>
    </ZDialog>
    <ZDialog v-model="reloadConfirm" title="放弃未保存修改？" :draggable="false">
      <p>重新加载会用已保存配置替换当前修改</p><template #footer>
        <ZButton @click="reloadConfirm = false">
          继续编辑
        </ZButton><ZButton type="primary" @click="reloadConfirm = false; load()">
          放弃并重新加载
        </ZButton>
      </template>
    </ZDialog>
  </section>
</template>
