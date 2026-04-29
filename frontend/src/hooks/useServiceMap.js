import { useMemo, useCallback } from 'react'

// Returns a stable serviceName(id) lookup backed by an O(1) Map.
// Falls back to the raw id when the service is unknown.
export function useServiceMap(services) {
  const map = useMemo(() => {
    const m = new Map()
    if (Array.isArray(services)) {
      for (const s of services) {
        if (s && s.id != null) m.set(s.id, s)
      }
    }
    return m
  }, [services])

  const serviceName = useCallback((id) => {
    const s = map.get(id)
    return s ? s.name : id
  }, [map])

  return { map, serviceName }
}
