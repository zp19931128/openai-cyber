import type { PluginHost } from '../api/types'

declare global {
  interface Window {
    readonly codexProxyPlugin?: PluginHost
  }
}
