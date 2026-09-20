import type { WebSocketInstance } from '@geastack/core'
import type { ClientCommand, ServerEvent } from './protocol'
import { parseServerEvent } from './protocol'

export type LinkStatus = 'offline' | 'connecting' | 'online'

/**
 * Control-channel client for the `filetransfer bridge` process.
 *
 * Everything here is callback driven on purpose: the GeaStack runtime has no
 * Promise, and its `fetch` is synchronous, so a socket plus callbacks is the
 * only non-blocking shape available on both the web and native targets.
 */
export class BridgeClient {
  private ws: WebSocketInstance | null = null
  private url = ''
  private retryMs = 500
  private retryTimer = 0
  private closedByUs = false

  onEvent: ((event: ServerEvent) => void) | null = null
  onStatus: ((status: LinkStatus, detail: string) => void) | null = null

  status: LinkStatus = 'offline'

  /** Secret presented to the bridge on connect; set before `connect`. */
  secret = ''

  connect(url: string): void {
    this.closedByUs = false
    this.url = url
    this.openSocket()
  }

  private openSocket(): void {
    this.clearRetry()
    this.setStatus('connecting', this.url)

    const ws = new WebSocket(this.url)
    this.ws = ws

    ws.onopen = () => {
      // Only a completed handshake proves the bridge is reachable, so the
      // backoff is reset here rather than at connect() time.
      this.retryMs = 500
      this.setStatus('online', this.url)
      // The bridge answers a successful auth with the catalog, so this is the
      // only command needed to bring the list up.
      this.send({ type: 'auth', secret: this.secret })
    }

    ws.onmessage = (event) => {
      const parsed = parseServerEvent(event.data)
      if (parsed !== null && this.onEvent !== null) this.onEvent(parsed)
    }

    ws.onerror = (event) => {
      this.setStatus('offline', event.message)
    }

    ws.onclose = (event) => {
      this.ws = null
      this.setStatus('offline', event.reason)
      if (!this.closedByUs) this.scheduleRetry()
    }
  }

  private scheduleRetry(): void {
    this.clearRetry()
    const wait = this.retryMs
    // Cap the backoff: a phone that walks out of WiFi range should rejoin
    // within a few seconds of coming back, not minutes later.
    this.retryMs = this.retryMs < 8000 ? this.retryMs * 2 : 8000
    this.retryTimer = setTimeout(() => {
      this.retryTimer = 0
      if (!this.closedByUs) this.openSocket()
    }, wait)
  }

  private clearRetry(): void {
    if (this.retryTimer !== 0) {
      clearTimeout(this.retryTimer)
      this.retryTimer = 0
    }
  }

  send(command: ClientCommand): boolean {
    const ws = this.ws
    if (ws === null || ws.readyState !== WebSocket.OPEN) return false
    ws.send(JSON.stringify(command))
    return true
  }

  close(): void {
    this.closedByUs = true
    this.clearRetry()
    const ws = this.ws
    this.ws = null
    if (ws !== null) ws.close()
    this.setStatus('offline', '')
  }

  private setStatus(status: LinkStatus, detail: string): void {
    this.status = status
    if (this.onStatus !== null) this.onStatus(status, detail)
  }
}

const BRIDGE_KEY = 'filetransfer.bridgeUrl'
const SECRET_KEY = 'filetransfer.secret'
const PEER_KEY = 'filetransfer.peer'

/**
 * Remembered bridge URL, defaulting to a bridge on this machine.
 *
 * The app cannot derive it: the runtime's `window` exposes only innerWidth and
 * innerHeight, so there is no page location to read. A phone therefore needs the
 * host's LAN address typed once under Setup, which is why that panel opens on
 * first run.
 */
export function savedBridgeUrl(): string {
  const stored = localStorage.getItem(BRIDGE_KEY)
  return stored !== '' ? stored : 'ws://localhost:8080/api/ws'
}

export function saveBridgeUrl(url: string): void {
  localStorage.setItem(BRIDGE_KEY, url)
}

export function savedSecret(): string {
  return localStorage.getItem(SECRET_KEY)
}

export function saveSecret(secret: string): void {
  localStorage.setItem(SECRET_KEY, secret)
}

export function savedPeer(): string {
  return localStorage.getItem(PEER_KEY)
}

export function savePeer(peer: string): void {
  localStorage.setItem(PEER_KEY, peer)
}
