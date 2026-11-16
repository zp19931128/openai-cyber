// @env browser
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export class PluginRequestError extends Error {
  constructor(message: string, readonly status: number, readonly code: string | null) {
    super(message)
    this.name = 'PluginRequestError'
  }
}

export default async function request(path: string, data?: unknown): Promise<unknown> {
  const host = window.codexProxyPlugin
  if (!host || host.version !== 2)
    throw new Error('请从 CPR 的插件页面打开管理页面')

  const reply = await host.request({
    path,
    method: data === undefined ? 'GET' : 'POST',
    ...(data === undefined ? {} : { contentType: 'application/json', body: JSON.stringify(data) }),
  })
  if (reply.contentType.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json')
    throw new Error('插件返回了不支持的内容类型')

  let value: unknown
  try {
    value = JSON.parse(new TextDecoder().decode(reply.body))
  }
  catch {
    throw new Error('插件返回了无效 JSON')
  }
  if (reply.status < 200 || reply.status >= 300) {
    const message = isRecord(value) && isRecord(value.error) && typeof value.error.message === 'string'
      ? `${value.error.message}${typeof value.error.details === 'string' ? `：${value.error.details}` : ''}`
      : `插件请求失败（HTTP ${reply.status}）`
    const code = isRecord(value) && isRecord(value.error) && typeof value.error.code === 'string' ? value.error.code : null
    throw new PluginRequestError(message, reply.status, code)
  }
  return value
}
