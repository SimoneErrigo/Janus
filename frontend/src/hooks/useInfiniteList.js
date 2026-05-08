import { useState, useEffect, useRef, useCallback } from 'react'

/**
 * useInfiniteList — generic infinite-scroll hook.
 *
 * @param fetchPage  async (offset, limit) => { items: [], total: number }
 * @param pageSize   rows per page (default 50)
 *
 * Returns:
 *   items       — accumulated list
 *   total       — total matching rows (from backend)
 *   loading     — true while a fetch is in-flight
 *   hasMore     — true when there are more rows to load
 *   sentinelRef — attach to a DOM element; when it enters the viewport the
 *                 next page is automatically fetched
 *   prepend(newItems, sortDesc) — prepend SSE-pushed items, dedup by id
 *   refresh()   — re-fetch the currently visible window (0..loaded)
 *   reset()     — discard list and fetch page 0 (call on filter change)
 */
export function useInfiniteList({ fetchPage, pageSize = 50 }) {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [hasMore, setHasMore] = useState(true)

  // Stable refs so callbacks never go stale
  const fetchPageRef = useRef(fetchPage)
  useEffect(() => { fetchPageRef.current = fetchPage }, [fetchPage])

  const offsetRef = useRef(0)
  const inflightRef = useRef(0)       // count of in-flight requests (for spinner)
  const latestReqRef = useRef(0)      // monotonically increasing request id
  // The last request whose results were committed. Any response with a reqId
  // <= this value is stale (a newer reset/refresh/append already superseded it).
  const committedReqRef = useRef(0)
  // Mirror hasMore in a ref so the IntersectionObserver callback doesn't depend
  // on React state (avoids re-attaching the observer, avoids stale-closure
  // bugs, and avoids the old DOM-attribute approach which could be clobbered by
  // the consuming component's JSX).
  const hasMoreRef = useRef(true)
  useEffect(() => { hasMoreRef.current = hasMore }, [hasMore])
  // Append-only lock: prevents double-firing fetchNext when the observer
  // triggers rapidly. Independent of reset/refresh, which must always run.
  const appendingRef = useRef(false)

  function beginRequest() {
    const id = ++latestReqRef.current
    inflightRef.current++
    setLoading(true)
    return id
  }
  function endRequest() {
    inflightRef.current = Math.max(0, inflightRef.current - 1)
    if (inflightRef.current === 0) setLoading(false)
  }

  // Append-next-page fetch (used by the scroll sentinel). Coalesced per-append
  // only — reset/refresh running in parallel is fine and expected.
  const fetchNext = useCallback(async (offset) => {
    if (appendingRef.current) return
    if (!hasMoreRef.current) return
    appendingRef.current = true
    const reqId = beginRequest()
    try {
      const result = await fetchPageRef.current(offset, pageSize)
      // If a reset/refresh committed after us, drop our result — their view is
      // authoritative.
      if (reqId <= committedReqRef.current) return
      committedReqRef.current = reqId
      const newItems = result.items || []
      const newTotal = result.total ?? 0
      let advancedOffset = offset + newItems.length
      setTotal(newTotal)
      setItems((prev) => {
        const seen = new Set(prev.map((i) => i.id))
        const fresh = newItems.filter((i) => !seen.has(i.id))
        return fresh.length ? [...prev, ...fresh] : prev
      })
      // Keep offset in sync with the backend pagination. If we received fewer
      // rows than pageSize the backend has signalled "end of range".
      offsetRef.current = advancedOffset
      const endReached = newItems.length < pageSize
      setHasMore(!endReached && (newTotal === 0 || advancedOffset < newTotal))
    } catch (err) {
      console.error('useInfiniteList fetch error:', err)
    } finally {
      appendingRef.current = false
      endRequest()
    }
  }, [pageSize])

  // Sentinel: triggers next page when scrolled into view
  const sentinelRef = useRef(null)
  useEffect(() => {
    const el = sentinelRef.current
    if (!el) return
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMoreRef.current && !appendingRef.current) {
          fetchNext(offsetRef.current)
        }
      },
      { rootMargin: '300px' },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [fetchNext])

  const combinedSentinelRef = useCallback((el) => {
    sentinelRef.current = el
  }, [])

  // reset: discard list and load page 0. ALWAYS runs — supersedes any in-flight
  // fetch. This is the critical path for filter changes: the latest reset must
  // win, regardless of what's in flight.
  const reset = useCallback(async () => {
    const reqId = beginRequest()
    try {
      const result = await fetchPageRef.current(0, pageSize)
      if (reqId < latestReqRef.current) return  // a newer reset/refresh was queued
      committedReqRef.current = reqId
      const newItems = result.items || []
      const newTotal = result.total ?? 0
      offsetRef.current = newItems.length
      setTotal(newTotal)
      const endReached = newItems.length < pageSize
      setHasMore(!endReached && (newTotal === 0 || newItems.length < newTotal))
      setItems(newItems)
    } catch (err) {
      console.error('useInfiniteList reset error:', err)
    } finally {
      endRequest()
    }
  }, [pageSize])

  // refresh: re-fetch the currently loaded window so metadata updates show up.
  // Also always runs (supersedes in-flight).
  const refresh = useCallback(async () => {
    const count = Math.max(offsetRef.current, pageSize)
    const reqId = beginRequest()
    try {
      const result = await fetchPageRef.current(0, count)
      if (reqId < latestReqRef.current) return
      committedReqRef.current = reqId
      const newItems = result.items || []
      const newTotal = result.total ?? 0
      offsetRef.current = newItems.length
      setTotal(newTotal)
      const endReached = newItems.length < count
      setHasMore(!endReached && (newTotal === 0 || newItems.length < newTotal))
      setItems(newItems)
    } catch {}
    finally {
      endRequest()
    }
  }, [pageSize])

  // prepend: merge SSE-pushed items into the top of the list
  const prepend = useCallback((newItems, sortDesc = true) => {
    if (!newItems.length) return
    setItems((prev) => {
      const map = new Map()
      for (const p of newItems) map.set(p.id, p)
      for (const p of prev) {
        if (!map.has(p.id)) map.set(p.id, p)
      }
      const merged = Array.from(map.values())
      merged.sort((a, b) => (sortDesc ? b.id - a.id : a.id - b.id))
      return merged
    })
    // Do not adjust `total` here: backend total already accounts for these rows.
    // A subsequent refresh/reset will reconcile counts precisely.
  }, [])

  return {
    items,
    total,
    loading,
    hasMore,
    sentinelRef: combinedSentinelRef,
    prepend,
    refresh,
    reset,
  }
}
