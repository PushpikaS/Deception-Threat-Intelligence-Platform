import { useEffect, useRef, useState } from 'react'

const WS_URL = import.meta.env.VITE_WS_URL
  || `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/ws/live`

export function useLiveFeed(enabled = true, onMessage) {
  const [connected, setConnected] = useState(false)
  const [lastEvent, setLastEvent] = useState(null)
  const wsRef = useRef(null)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  useEffect(() => {
    if (!enabled) return undefined
    let closed = false
    let retryTimer

    const connect = () => {
      if (closed) return
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws
      ws.onopen = () => setConnected(true)
      ws.onclose = () => {
        setConnected(false)
        if (!closed) retryTimer = setTimeout(connect, 4000)
      }
      ws.onerror = () => ws.close()
      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data)
          setLastEvent(data)
          onMessageRef.current?.(data)
        } catch { /* ignore */ }
      }
    }

    connect()
    return () => {
      closed = true
      clearTimeout(retryTimer)
      wsRef.current?.close()
    }
  }, [enabled])

  return { connected, lastEvent }
}