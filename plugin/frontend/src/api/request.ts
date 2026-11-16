// @env browser
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export default async function request(path: string): Promise<unknown> {
  const host = window.codexProxyPlugin
  if (!host || host.version !== 2)
    throw new Error('请从 CPR 的插件页面打开拦截日志')

  const reply = await host.request({ method: 'GET', path })
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
      ? value.error.message
      : `日志读取失败（HTTP ${reply.status}）`
    throw new Error(message)
  }
  return value
}
