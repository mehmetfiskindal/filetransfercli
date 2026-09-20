import { ReactiveComponent, mount } from '@geastack/core'
import './styles.css'

import { BridgeClient } from './bridge'
import type { LinkStatus } from './bridge'
import {
  savedBridgeUrl,
  saveBridgeUrl,
  savedSecret,
  saveSecret,
  savedPeer,
  savePeer
} from './bridge'
import type { Peer, RemoteFile, ServerEvent, TransferProgress } from './protocol'
import { baseName, humanBytes, humanEta, humanRate, percent } from './format'

export class App extends ReactiveComponent {
  private link: LinkStatus = 'offline'
  private linkDetail = ''

  private root = ''
  private bridgeHost = ''
  private files: RemoteFile[] = []
  private peers: Peer[] = []

  /** Selected paths as a set-shaped record; reassigned so the view re-renders. */
  private selected: Record<string, boolean> = {}

  private items: TransferProgress[] = []
  private sent = 0
  private total = 0
  private rate = 0
  private running = false
  private activeId = 0

  private summary = ''
  private error = ''

  private settingsOpen = false
  private bridgeUrl = savedBridgeUrl()
  private secret = savedSecret()
  private peer = savedPeer()

  private client = new BridgeClient()

  constructor() {
    super()
    this.client.onStatus = (status, detail) => {
      this.link = status
      this.linkDetail = detail
      if (status !== 'online') this.running = false
    }
    this.client.onEvent = (event) => this.apply(event)
    // An unset secret or peer is the normal first-run state, so open the setup
    // panel instead of letting a connect attempt fail silently.
    this.settingsOpen = this.secret === '' || this.peer === ''
    this.client.secret = this.secret
    this.client.connect(this.bridgeUrl)
  }

  private apply(event: ServerEvent): void {
    switch (event.type) {
      case 'hello':
        this.bridgeHost = event.host
        this.root = event.root
        break
      case 'catalog':
        this.root = event.root
        this.files = event.files
        this.peers = event.peers
        if (this.peer === '' && event.peers.length > 0) this.peer = event.peers[0].addr
        break
      case 'progress':
        this.items = event.items
        this.sent = event.sent
        this.total = event.total
        this.rate = event.bytesPerSecond
        this.running = true
        // Cancel is addressed to a specific transfer, so remember which one the
        // bridge is reporting on.
        if (event.items.length > 0) this.activeId = event.items[0].id
        break
      case 'done':
        this.running = false
        this.rate = 0
        this.activeId = 0
        this.summary = `Sent ${event.files} file(s), ${humanBytes(event.bytes)} in ${event.seconds.toFixed(1)}s`
        this.client.send({ type: 'list' })
        break
      case 'error':
        this.error = event.message
        this.running = false
        break
    }
  }

  private selectedPaths(): string[] {
    const paths: string[] = []
    for (const file of this.files) {
      if (this.selected[file.path] === true) paths.push(file.path)
    }
    return paths
  }

  private selectedBytes(): number {
    let bytes = 0
    for (const file of this.files) {
      if (this.selected[file.path] === true) bytes += file.size
    }
    return bytes
  }

  private toggle(path: string): void {
    const next: Record<string, boolean> = {}
    for (const key in this.selected) next[key] = this.selected[key]
    next[path] = this.selected[path] !== true
    this.selected = next
  }

  private toggleAll(): void {
    const selectAll = this.selectedPaths().length < this.files.length
    const next: Record<string, boolean> = {}
    if (selectAll) {
      for (const file of this.files) next[file.path] = true
    }
    this.selected = next
  }

  private startSend(): void {
    this.error = ''
    this.summary = ''
    const paths = this.selectedPaths()
    if (paths.length === 0) {
      this.error = 'Select at least one file.'
      return
    }
    if (this.peer === '') {
      this.error = 'Set a peer address first.'
      this.settingsOpen = true
      return
    }
    if (this.secret === '') {
      this.error = 'Set the shared secret first.'
      this.settingsOpen = true
      return
    }
    const queued = this.client.send({
      type: 'send',
      to: this.peer,
      secret: this.secret,
      paths
    })
    if (!queued) {
      this.error = 'Bridge is offline.'
      return
    }
    this.running = true
    this.sent = 0
    this.total = this.selectedBytes()
    this.rate = 0
  }

  private cancel(): void {
    this.client.send({ type: 'cancel', id: this.activeId })
    this.running = false
  }

  private reconnect(): void {
    saveBridgeUrl(this.bridgeUrl)
    saveSecret(this.secret)
    savePeer(this.peer)
    this.error = ''
    this.client.secret = this.secret
    this.client.close()
    this.client.connect(this.bridgeUrl)
  }

  private statusLabel(): string {
    if (this.link === 'online') {
      return this.bridgeHost !== '' ? this.bridgeHost : 'connected'
    }
    if (this.link === 'connecting') return 'connecting…'
    return this.linkDetail !== '' ? this.linkDetail : 'offline'
  }

  template() {
    const chosen = this.selectedPaths().length
    const pct = percent(this.sent, this.total)
    const hasFiles = this.files.length > 0

    // Every branch below holds JSX written out in place, and each `.map` is a
    // direct child of its container. The compiler replaces a ternary branch
    // that is a method call or a `.map` with an empty comment, so panels are
    // shown and hidden with `display` instead of being swapped in and out.
    return (
      <div class="app">
        <div class="topbar">
          <div class="brand-wrap">
            <span class="brand">File Transfer</span>
            <span class="host">{this.statusLabel()}</span>
          </div>
          <div class={`dot dot-${this.link}`} />
          <button class="btn btn-ghost" onClick={() => (this.settingsOpen = !this.settingsOpen)}>
            Setup
          </button>
        </div>

        <div class="settings" style={{ display: this.settingsOpen ? 'flex' : 'none' }}>
          <label class="field-label">Bridge</label>
          <input
            type="text"
            class="field"
            value={this.bridgeUrl}
            placeholder="ws://192.168.1.10:8080/api/ws"
            onInput={(event) => {
              this.bridgeUrl = event.target.value
            }}
          />
          <label class="field-label">Peer</label>
          <input
            type="text"
            class="field"
            value={this.peer}
            placeholder="192.168.1.20:8443"
            onInput={(event) => {
              this.peer = event.target.value
            }}
          />
          <label class="field-label">Shared secret</label>
          <input
            type="password"
            class="field"
            value={this.secret}
            placeholder="same on both sides"
            onInput={(event) => {
              this.secret = event.target.value
            }}
          />
          <button class="btn btn-primary" onClick={() => this.reconnect()}>
            Save and reconnect
          </button>
        </div>

        {this.error !== '' ? <div class="banner banner-error">{this.error}</div> : null}
        {this.summary !== '' ? <div class="banner banner-ok">{this.summary}</div> : null}

        <div class="transfers" style={{ display: this.running ? 'flex' : 'none' }}>
          {this.items.map((item) => (
            <div class="xfer">
              <div class="xfer-head">
                <span class="xfer-name">{baseName(item.path)}</span>
                <span class={`xfer-state state-${item.state}`}>{item.state}</span>
              </div>
              <div class="bar">
                <div class="bar-fill" style={{ width: `${percent(item.sent, item.total)}%` }} />
              </div>
              <div class="xfer-foot">
                <span class="muted">
                  {humanBytes(item.sent)} / {humanBytes(item.total)}
                </span>
                <span class="resumed" style={{ display: item.resumed > 0 ? 'flex' : 'none' }}>
                  resumed at {humanBytes(item.resumed)}
                </span>
                <span class="muted">{humanRate(item.bytesPerSecond)}</span>
              </div>
              <span class="row-error" style={{ display: item.error !== '' ? 'flex' : 'none' }}>
                {item.error}
              </span>
            </div>
          ))}
        </div>

        <div class="listwrap" style={{ display: this.running ? 'none' : 'flex' }}>
          <div class="section">
            <span class="section-title">{this.root !== '' ? this.root : 'No bridge'}</span>
            <button class="btn btn-ghost" onClick={() => this.toggleAll()}>
              {chosen < this.files.length ? 'Select all' : 'Clear'}
            </button>
          </div>
          <div class="empty" style={{ display: hasFiles ? 'none' : 'flex' }}>
            <span class="empty-title">Nothing to show</span>
            <span class="empty-copy">
              Run `filetransfer bridge` on the machine holding your files, then set the bridge
              address under Setup.
            </span>
          </div>
          <div class="list" style={{ display: hasFiles ? 'flex' : 'none' }}>
            {this.files.map((file) => (
              <div
                class={`row ${this.selected[file.path] === true ? 'row-on' : ''}`}
                onClick={() => this.toggle(file.path)}
              >
                <div class={`check ${this.selected[file.path] === true ? 'check-on' : ''}`} />
                <div class="row-text">
                  <span class="row-name">{baseName(file.path)}</span>
                  <span class="row-path">{file.path}</span>
                </div>
                <span class="row-size">{humanBytes(file.size)}</span>
              </div>
            ))}
          </div>
        </div>

        <div class="footer">
          <div class="bar bar-lg">
            <div class="bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <div class="footer-stats">
            <span class="stat-main">
              {this.running ? `${humanBytes(this.sent)} / ${humanBytes(this.total)}` : `${chosen} selected`}
            </span>
            <span class="muted">
              {this.running
                ? `${humanRate(this.rate)} · ${humanEta(this.total - this.sent, this.rate)}`
                : humanBytes(this.selectedBytes())}
            </span>
          </div>
          {this.running ? (
            <button class="btn btn-danger" onClick={() => this.cancel()}>
              Cancel
            </button>
          ) : (
            <button class="btn btn-primary" onClick={() => this.startSend()}>
              Send
            </button>
          )}
        </div>
      </div>
    )
  }
}

mount(App)
