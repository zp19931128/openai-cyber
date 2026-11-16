<script setup lang="ts">
import type { AuditSnapshot } from './api/types'
import { ZButton, ZConfigProvider, ZInput, ZSelect } from '@codex-proxy/ui'
import { zhHans } from '@codex-proxy/ui/locale'
import { ChevronDown, RefreshCw, Search, ShieldAlert } from '@lucide/vue'
import { computed, onMounted, ref, watch } from 'vue'
import { getAudit } from './api/modules/audit'

defineProps<{ preview: boolean }>()

const snapshot = ref<AuditSnapshot | null>(null)
const loading = ref(false)
const error = ref('')
const search = ref('')
const category = ref('')
const page = ref(1)
const pageSize = 10
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
}
const categoryOptions = computed(() => [
  { label: '全部类别', value: '' },
  ...[...new Set(snapshot.value?.events.map(event => event.category ?? 'inspection_failed'))].sort().map(value => ({
    label: categoryNames[value] ?? (value === 'inspection_failed' ? '检查未完成' : value),
    value,
  })),
])
const filtered = computed(() => {
  const term = search.value.trim().toLocaleLowerCase()
  return (snapshot.value?.events ?? []).filter(event =>
    (!category.value || (event.category ?? 'inspection_failed') === category.value)
    && (!term || [event.request_id, event.client_key_id, event.model, event.rule_id, event.category, event.reason, event.context]
      .some(value => value?.toLocaleLowerCase().includes(term))),
  ).sort((a, b) => b.timestamp_ms - a.timestamp_ms)
})
const pageCount = computed(() => Math.max(1, Math.ceil(filtered.value.length / pageSize)))
const events = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize))

watch([search, category], () => {
  page.value = 1
})
watch(pageCount, (count) => {
  page.value = Math.min(page.value, count)
})

function timestamp(milliseconds: number): string {
  const date = new Date(milliseconds)
  return Number.isNaN(date.valueOf()) ? '未知时间' : `${date.toISOString().replace('T', ' ').slice(0, 19)} UTC`
}

async function refresh() {
  if (loading.value)
    return
  loading.value = true
  error.value = ''
  try {
    snapshot.value = await getAudit()
  }
  catch (cause) {
    error.value = cause instanceof Error ? cause.message : '日志读取失败，请重试'
  }
  finally {
    loading.value = false
  }
}

onMounted(refresh)
</script>

<template>
  <ZConfigProvider :locale="zhHans">
    <main class="grid min-w-0 gap-4 font-sans text-z-sm text-z-text" :class="{ 'p-4': preview }">
      <div v-if="preview" class="rounded-z bg-z-warning-container px-3 py-2 text-z-xs text-z-warning-on-container" role="note">
        独立模拟预览，不代表线上拦截记录或宿主安装结果
      </div>

      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span class="inline-flex items-center gap-2 font-emphasis">
            <ShieldAlert class="size-4 text-z-error-text" aria-hidden="true" />
            已保留 {{ snapshot?.events.length ?? '—' }} 条拦截记录
          </span>
          <span v-if="snapshot" class="text-z-xs text-z-text-secondary">
            最近 {{ snapshot.retention.retention_days }} 天 · 最多 {{ snapshot.retention.max_events }} 条
          </span>
        </div>
        <ZButton :loading="loading" @click="refresh">
          <RefreshCw class="size-4" aria-hidden="true" />
          刷新
        </ZButton>
      </div>

      <div v-if="error" class="rounded-z bg-z-error-container px-3 py-2 text-z-error-on-container" role="alert">
        {{ error }}<span v-if="snapshot">，下方仍显示上次读取的记录</span>
      </div>
      <div v-if="snapshot && snapshot.recording.failures_since_start > 0" class="rounded-z bg-z-warning-container px-3 py-2 text-z-warning-on-container" role="alert">
        本次运行有 {{ snapshot.recording.failures_since_start }} 次日志写入失败，部分拦截记录可能缺失
        <span v-if="snapshot.recording.last_error_at_ms" class="block text-z-xs">最近发生于 {{ timestamp(snapshot.recording.last_error_at_ms) }}</span>
      </div>

      <div class="grid min-w-0 gap-3 sm:grid-cols-[minmax(12rem,1fr)_minmax(12rem,16rem)]">
        <ZInput v-model="search" placeholder="搜索请求 ID、规则或上下文" aria-label="搜索拦截记录" :disabled="!snapshot">
          <template #prefix>
            <Search class="size-4" aria-hidden="true" />
          </template>
        </ZInput>
        <ZSelect v-model="category" :options="categoryOptions" :disabled="!snapshot" aria-label="拦截类别" />
      </div>

      <div v-if="loading && !snapshot" class="py-12 text-center text-z-text-secondary" role="status">
        正在读取拦截日志
      </div>
      <div v-else-if="!snapshot && error" class="py-10 text-center text-z-text-secondary">
        暂时无法显示日志，请刷新重试
      </div>
      <div v-else-if="snapshot && !snapshot.events.length" class="rounded-z-card bg-z-bg-container px-4 py-10 text-center shadow-z-card">
        <p class="font-emphasis">
          暂无拦截记录
        </p>
        <p class="mt-2 text-z-xs text-z-text-secondary">
          仅记录升级后被本插件拦截的请求，空列表不代表插件已绑定或请求已通过检查
        </p>
      </div>
      <div v-else-if="snapshot && !filtered.length" class="py-10 text-center text-z-text-secondary">
        没有符合筛选条件的记录
      </div>
      <div v-else class="grid min-w-0 gap-2">
        <details v-for="event in events" :key="event.id" class="group min-w-0 rounded-z-card bg-z-bg-container shadow-z-card">
          <summary class="flex cursor-pointer list-none flex-wrap items-center gap-x-4 gap-y-2 rounded-z-card px-4 py-3 hover:bg-z-fill-quaternary focus-visible:outline-2 focus-visible:outline-z-primary [&::-webkit-details-marker]:hidden">
            <div class="min-w-0 flex-1 basis-64">
              <div class="flex flex-wrap items-center gap-2">
                <span class="rounded-z-sm bg-z-error-container px-2 py-0.5 text-z-xs font-emphasis text-z-error-on-container">已拦截</span>
                <span class="font-emphasis">{{ categoryNames[event.category ?? ''] ?? event.category ?? '检查未完成' }}</span>
              </div>
              <p class="mt-1 break-all font-mono text-z-xs text-z-text-secondary">
                {{ event.request_id || '无请求 ID' }}
              </p>
            </div>
            <div class="text-z-xs text-z-text-secondary">
              <p>{{ timestamp(event.timestamp_ms) }}</p>
              <p class="mt-1 break-all">
                {{ event.model ?? '未知模型' }} · {{ event.transport.toUpperCase() }}
              </p>
            </div>
            <span class="inline-flex items-center gap-1 text-z-xs text-z-text-secondary">
              详情<ChevronDown class="size-4 transition-transform group-open:rotate-180" aria-hidden="true" />
            </span>
          </summary>
          <div class="grid min-w-0 gap-4 px-4 pb-4 pt-1">
            <dl class="grid min-w-0 gap-x-6 gap-y-3 text-z-xs sm:grid-cols-2">
              <div>
                <dt class="text-z-text-secondary">
                  命中规则
                </dt><dd class="mt-1 break-all font-mono">
                  {{ event.rule_id ?? '—' }}
                </dd>
              </div>
              <div>
                <dt class="text-z-text-secondary">
                  客户端 Key ID
                </dt><dd class="mt-1 break-all font-mono">
                  {{ event.client_key_id ?? '—' }}
                </dd>
              </div>
              <div>
                <dt class="text-z-text-secondary">
                  拒绝原因
                </dt><dd class="mt-1 break-words">
                  {{ event.reason }}
                </dd>
              </div>
              <div>
                <dt class="text-z-text-secondary">
                  词库版本
                </dt><dd class="mt-1 break-all font-mono">
                  {{ event.policy_version ?? '—' }}
                </dd>
              </div>
            </dl>
            <div class="min-w-0">
              <p class="mb-2 text-z-xs font-emphasis">
                请求上下文<span v-if="event.context_truncated" class="ml-2 font-normal text-z-warning-text">已截断</span>
              </p>
              <pre v-if="event.context" class="whitespace-pre-wrap break-words rounded-z bg-z-fill-quaternary p-3 font-mono text-z-xs leading-relaxed">{{ event.context }}</pre>
              <p v-else class="text-z-xs text-z-text-secondary">
                此记录没有保存可查看的上下文
              </p>
            </div>
          </div>
        </details>
      </div>

      <div v-if="snapshot" class="flex flex-wrap items-center justify-between gap-3 text-z-xs text-z-text-secondary">
        <span>筛选后 {{ filtered.length }} 条 · 第 {{ page }} / {{ pageCount }} 页</span>
        <div class="flex gap-2">
          <ZButton size="small" :disabled="page === 1" @click="page--">
            上一页
          </ZButton>
          <ZButton size="small" :disabled="page === pageCount" @click="page++">
            下一页
          </ZButton>
        </div>
      </div>

      <details v-if="snapshot" class="text-z-xs text-z-text-secondary">
        <summary class="w-fit cursor-pointer rounded-z py-1 focus-visible:outline-2 focus-visible:outline-z-primary">
          上下文与保留范围
        </summary>
        <div class="grid gap-1.5 pt-2">
          <p>上下文保存{{ snapshot.retention.capture_context ? '已开启' : '已关闭' }}，仅保存被拦截请求本次携带的文本，常见密钥会被脱敏</p>
          <p>每条最多 {{ snapshot.retention.max_context_chars }} 字，不会通过 previous_response_id 回查历史会话</p>
          <p>按 {{ snapshot.retention.retention_days }} 天、{{ snapshot.retention.max_events }} 条和总大小 {{ Math.round(snapshot.retention.max_bytes / 1024) }} KiB 限制保留，条数可能少于上限</p>
        </div>
      </details>
    </main>
  </ZConfigProvider>
</template>
