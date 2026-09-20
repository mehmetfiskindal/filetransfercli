// Wire format for the control channel between this app and the `filetransfer
// bridge` process. Text JSON only: the GeaStack WebSocket sends strings, so the
// file bytes never travel over this channel. They move machine-to-machine over
// the existing TLS transfer engine, and the bridge reports byte counters back
// here as progress events.

/** A file the bridge is willing to expose, relative to the bridge's root. */
export interface RemoteFile {
  path: string
  size: number
  modTime: number
}

/** A peer the bridge can push to, as `host:port`. */
export interface Peer {
  addr: string
  label: string
}

export type TransferState = 'queued' | 'hashing' | 'running' | 'done' | 'failed' | 'skipped'

/** One file's live position in a transfer, as last reported by the bridge. */
export interface TransferProgress {
  id: number
  path: string
  state: TransferState
  /** Bytes already on the far side, including bytes skipped by resume. */
  sent: number
  total: number
  /** Bytes the receiver already had, so the UI can show resume credit. */
  resumed: number
  bytesPerSecond: number
  error: string
}

// ---------------------------------------------------------------------------
// app -> bridge
// ---------------------------------------------------------------------------

/** Presents the bridge secret; the bridge replies with the catalog. */
export interface AuthCommand {
  type: 'auth'
  secret: string
}

export interface ListCommand {
  type: 'list'
}

export interface SendCommand {
  type: 'send'
  to: string
  secret: string
  paths: string[]
}

export interface CancelCommand {
  type: 'cancel'
  id: number
}

export type ClientCommand = AuthCommand | ListCommand | SendCommand | CancelCommand

// ---------------------------------------------------------------------------
// bridge -> app
// ---------------------------------------------------------------------------

export interface HelloEvent {
  type: 'hello'
  host: string
  version: string
  root: string
  chunkSize: number
  /** True when the bridge process can stream file bytes to/from this client. */
  canStream: boolean
  /** True when the bridge was started with a secret and expects `auth`. */
  authRequired: boolean
}

export interface CatalogEvent {
  type: 'catalog'
  root: string
  files: RemoteFile[]
  peers: Peer[]
}

export interface ProgressEvent {
  type: 'progress'
  items: TransferProgress[]
  /** Aggregate across the whole batch, so the UI needs no summing pass. */
  sent: number
  total: number
  bytesPerSecond: number
}

export interface DoneEvent {
  type: 'done'
  id: number
  files: number
  bytes: number
  seconds: number
}

export interface ErrorEvent {
  type: 'error'
  message: string
}

export type ServerEvent = HelloEvent | CatalogEvent | ProgressEvent | DoneEvent | ErrorEvent

/**
 * Narrow a decoded control frame by its `type` tag.
 *
 * The runtime has no `instanceof` for plain JSON, so the tag is the only
 * discriminator available; an unknown tag returns null rather than throwing so
 * a newer bridge can add events without breaking an older app.
 */
export function parseServerEvent(text: string): ServerEvent | null {
  const raw = JSON.parse(text) as { type?: string }
  if (raw.type === undefined) return null
  switch (raw.type) {
    case 'hello':
      return JSON.parse(text) as HelloEvent
    case 'catalog':
      return JSON.parse(text) as CatalogEvent
    case 'progress':
      return JSON.parse(text) as ProgressEvent
    case 'done':
      return JSON.parse(text) as DoneEvent
    case 'error':
      return JSON.parse(text) as ErrorEvent
    default:
      return null
  }
}
