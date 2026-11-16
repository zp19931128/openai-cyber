<script setup lang="ts">
import { ZConfigProvider, ZSegmented } from '@codex-proxy/ui'
import { zhHans } from '@codex-proxy/ui/locale'
import { ref } from 'vue'
import AuditView from './views/AuditView.vue'
import RulesView from './views/RulesView.vue'

defineProps<{ preview: boolean }>()
const tab = ref('rules')
</script>

<template>
  <ZConfigProvider :locale="zhHans">
    <main class="grid min-w-0 gap-4 font-sans text-z-sm text-z-text" :class="{ 'p-4': preview }">
      <div v-if="preview" class="rounded-z bg-z-warning-container px-3 py-2 text-z-xs text-z-warning-on-container" role="note">
        独立模拟预览，不代表线上规则、拦截记录或宿主安装结果
      </div>
      <ZSegmented v-model="tab" aria-label="插件功能" :options="[{ label: '规则管理', value: 'rules' }, { label: '拦截日志', value: 'audit' }]" class="w-fit" />
      <RulesView v-show="tab === 'rules'" />
      <AuditView v-if="tab === 'audit'" :preview="false" />
    </main>
  </ZConfigProvider>
</template>
