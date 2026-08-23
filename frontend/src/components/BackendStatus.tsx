import {
  useEffect,
  useState,
} from 'react'

import { getHealth } from '../api/client'

type ConnectionState =
  | 'checking'
  | 'connected'
  | 'unavailable'

function BackendStatus() {
  const [connectionState, setConnectionState] =
    useState<ConnectionState>('checking')

  useEffect(() => {
    const controller = new AbortController()

    getHealth(controller.signal)
      .then(() => {
        setConnectionState('connected')
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setConnectionState('unavailable')
        }
      })

    return () => {
      controller.abort()
    }
  }, [])

  const labels: Record<ConnectionState, string> = {
    checking: 'Checking backend',
    connected: 'Backend connected',
    unavailable: 'Backend unavailable',
  }

  return (
    <div
      className="sidebar-footer"
      data-status={connectionState}
      aria-live="polite"
    >
      <span aria-hidden="true" />
      {labels[connectionState]}
    </div>
  )
}

export default BackendStatus