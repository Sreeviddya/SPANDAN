import useAuthStore from '../stores/authStore.js'
import { API_URL } from '../config.js'

// Install a one-time global fetch wrapper that turns any 401 from OUR backend into a graceful
// session-expiry: it drops the session and flags sessionExpired, so ProtectedRoute redirects to the
// login screen with a clear message — instead of the previous silent failure. (The answer-submit path
// in StudentRoomPage uses a raw fetch that swallowed the 401, so an expired student appeared "in the
// room" but simply could not answer.) Wrapping fetch once here covers every call site — the api.js
// helper, the stores, and any raw fetch — without editing each one.
//
// Login / registration 401s are NOT treated as expiry: those happen while no token is stored, and we
// only react when a token is currently present (a live session going stale). Cross-origin calls (e.g.
// the Samagama SSO probe to samagama.in) are ignored — only same-origin requests under API_URL count.
let installed = false

function isOurApiUrl(input) {
  const raw = typeof input === 'string' ? input : (input && input.url) || ''
  try {
    const u = new URL(raw, window.location.origin)
    if (u.host !== window.location.host) return false // cross-origin (e.g. samagama.in) → not ours
    return u.pathname.startsWith(API_URL)
  } catch {
    return false
  }
}

export function installAuthFetchInterceptor() {
  if (installed || typeof window === 'undefined' || !window.fetch) return
  installed = true
  const originalFetch = window.fetch.bind(window)

  window.fetch = async (...args) => {
    const isOurs = isOurApiUrl(args[0])

    let response
    try {
      response = await originalFetch(...args)
    } catch (err) {
      // Network-level failure (backend restarting, server down, proxy refused). Raw fetches would
      // surface a cryptic "Failed to fetch" (or, via a proxy that answers with an empty body, the
      // "Unexpected end of JSON input" when a caller does res.json()). Turn it into a structured
      // JSON error response so every call site gets a friendly message instead. Only for OUR API —
      // cross-origin probes (e.g. the Samagama SSO check) must see the real failure.
      if (isOurs) {
        return new Response(JSON.stringify({ error: 'Cannot reach the server. Please check your connection and try again.' }), {
          status: 503,
          statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'application/json' }
        })
      }
      throw err
    }

    try {
      if (isOurs) {
        if (response.status === 401 && useAuthStore.getState().token) {
          useAuthStore.getState().handleSessionExpired()
        }
        // A failing response with an EMPTY body (e.g. the dev proxy answers 500/502 with zero bytes
        // while the backend is restarting). Callers unconditionally res.json() that, and the raw
        // TypeError ends up in the UI. Detect and replace it with a JSON error payload so the error
        // shown is friendly and the parse never throws.
        if (!response.ok && !response.bodyUsed) {
          const text = await response.clone().text()
          if (text === '') {
            const error = (response.status === 502 || response.status === 503 || response.status === 504)
              ? 'The server is temporarily unavailable. Please try again.'
              : 'Something went wrong. Please try again.'
            return new Response(JSON.stringify({ error }), {
              status: response.status,
              statusText: response.statusText,
              headers: { 'Content-Type': 'application/json' }
            })
          }
        }
      }
    } catch {
      // Never let interceptor bookkeeping break the caller's response.
    }
    return response
  }
}

export default installAuthFetchInterceptor
