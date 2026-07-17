import { useState, useEffect, useRef, useCallback } from 'react'

/**
 * useInfiniteList — generic infinite-scroll hook.
 *
 * @param fetchPage  async (offset, limit, cursor) =>
 *                   { items: [], total: number, nextCursor?: string }
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
	const [error, setError] = useState('')
	const [totalExact, setTotalExact] = useState(true)
	const [partial, setPartial] = useState(false)

  // Stable refs so callbacks never go stale
  const fetchPageRef = useRef(fetchPage)
  useEffect(() => { fetchPageRef.current = fetchPage }, [fetchPage])

  const offsetRef = useRef(0)
  const cursorRef = useRef(null)
  const latestReqRef = useRef(0)      // monotonically increasing request id
  // Mirror hasMore in a ref so the IntersectionObserver callback doesn't depend
  // on React state (avoids re-attaching the observer, avoids stale-closure
  // bugs, and avoids the old DOM-attribute approach which could be clobbered by
  // the consuming component's JSX).
  const hasMoreRef = useRef(true)
  useEffect(() => { hasMoreRef.current = hasMore }, [hasMore])
  // Append-only lock: prevents double-firing fetchNext when the observer
  // triggers rapidly. Reloads invalidate this lock and temporarily prevent a
  // sentinel append from superseding their authoritative first-page result.
  const appendingRef = useRef(false)
  const appendReqRef = useRef(0)
  const reloadingRef = useRef(false)
  const reloadReqRef = useRef(0)
	const observerRef = useRef(null)
	const sentinelNodeRef = useRef(null)
	const rearmSentinel = useCallback(() => {
		const observer = observerRef.current
		const node = sentinelNodeRef.current
		if (!observer || !node) return
		observer.unobserve(node)
		observer.observe(node)
	}, [])

  useEffect(() => () => {
    latestReqRef.current++
    appendReqRef.current = 0
    reloadReqRef.current = 0
    cursorRef.current = null
    appendingRef.current = false
    reloadingRef.current = false
  }, [])

  function beginRequest() {
    const id = ++latestReqRef.current
    setLoading(true)
    return id
  }
  function endRequest(id) {
    if (id === latestReqRef.current) setLoading(false)
  }

  // Append-next-page fetch (used by the scroll sentinel). Coalesced per-append
  // only — reset/refresh running in parallel is fine and expected.
  const fetchNext = useCallback(async (offset) => {
    if (appendingRef.current) return
    if (reloadingRef.current) return
    if (!hasMoreRef.current) return
    appendingRef.current = true
    const reqId = beginRequest()
    appendReqRef.current = reqId
		let shouldRearm = false
    try {
      const result = await fetchPageRef.current(offset, pageSize, cursorRef.current)
      // Once any newer append/reset/refresh starts, this response is stale.
      // Applying the same rule to success and failure prevents an old request
      // from overwriting a newer view or its error state.
      if (reqId !== latestReqRef.current) return
      setError('')
      const newItems = result.items || []
      const newTotal = result.total ?? 0
	  const cursorAware = Object.prototype.hasOwnProperty.call(result, 'nextCursor')
	  cursorRef.current = cursorAware ? (result.nextCursor || null) : null
	  setTotalExact(result.totalExact !== false)
	  setPartial(!!result.partial)
      const advancedOffset = offset + newItems.length
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
      const canContinue = cursorAware
        ? !!result.nextCursor
        : !endReached && (newTotal === 0 || advancedOffset < newTotal)
		// An empty residual-filter page can still carry a continuation cursor
		// after the backend's bounded scan. Keep advancing instead of making
		// matches beyond that scan window unreachable.
		hasMoreRef.current = canContinue
		setHasMore(canContinue)
		shouldRearm = cursorAware && !!result.nextCursor && newItems.length === 0
    } catch (err) {
      if (reqId === latestReqRef.current) {
        setError(err?.message || 'Failed to load results')
        console.error('useInfiniteList fetch error:', err)
      }
    } finally {
      if (appendReqRef.current === reqId) {
        appendReqRef.current = 0
        appendingRef.current = false
      }
      endRequest(reqId)
		if (shouldRearm && reqId === latestReqRef.current) setTimeout(rearmSentinel, 0)
    }
  }, [pageSize, rearmSentinel])

  // Bind the observer in the callback ref so conditional sentinels (Traffic's
  // flow view) are observed again when React replaces their DOM node.
  const combinedSentinelRef = useCallback((el) => {
    observerRef.current?.disconnect()
    observerRef.current = null
		sentinelNodeRef.current = el
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
    observerRef.current = observer
  }, [fetchNext])

  useEffect(() => () => observerRef.current?.disconnect(), [])

  // reset: discard list and load page 0. ALWAYS runs — supersedes any in-flight
  // fetch. This is the critical path for filter changes: the latest reset must
  // win, regardless of what's in flight.
  const reset = useCallback(async () => {
    reloadingRef.current = true
    appendingRef.current = false
    appendReqRef.current = 0
    cursorRef.current = null
    const reqId = beginRequest()
    reloadReqRef.current = reqId
    try {
      const result = await fetchPageRef.current(0, pageSize, null)
      if (reqId !== latestReqRef.current) return
      setError('')
      const newItems = result.items || []
      const newTotal = result.total ?? 0
	  const cursorAware = Object.prototype.hasOwnProperty.call(result, 'nextCursor')
	  cursorRef.current = cursorAware ? (result.nextCursor || null) : null
	  setTotalExact(result.totalExact !== false)
	  setPartial(!!result.partial)
      offsetRef.current = newItems.length
      setTotal(newTotal)
      const endReached = newItems.length < pageSize
		const canContinue = cursorAware
			? !!result.nextCursor
			: !endReached && (newTotal === 0 || newItems.length < newTotal)
		hasMoreRef.current = canContinue
		setHasMore(canContinue)
      setItems(newItems)
    } catch (err) {
      if (reqId === latestReqRef.current) {
        setItems([])
        setTotal(0)
			hasMoreRef.current = false
        setHasMore(false)
        setError(err?.message || 'Invalid filter or failed query')
        setTotalExact(true)
        setPartial(false)
        console.error('useInfiniteList reset error:', err)
      }
    } finally {
      if (reloadReqRef.current === reqId) reloadingRef.current = false
      endRequest(reqId)
		if (reqId === latestReqRef.current) setTimeout(rearmSentinel, 0)
    }
  }, [pageSize, rearmSentinel])

  // refresh: re-fetch the currently loaded window so metadata updates show up.
  // Also always runs (supersedes in-flight).
  const refresh = useCallback(async () => {
    const count = Math.max(offsetRef.current, pageSize)
    reloadingRef.current = true
    appendingRef.current = false
    appendReqRef.current = 0
    cursorRef.current = null
    const reqId = beginRequest()
    reloadReqRef.current = reqId
    try {
      const result = await fetchPageRef.current(0, count, null)
      if (reqId !== latestReqRef.current) return
      setError('')
      const newItems = result.items || []
      const newTotal = result.total ?? 0
	  const cursorAware = Object.prototype.hasOwnProperty.call(result, 'nextCursor')
	  cursorRef.current = cursorAware ? (result.nextCursor || null) : null
	  setTotalExact(result.totalExact !== false)
	  setPartial(!!result.partial)
      offsetRef.current = newItems.length
      setTotal(newTotal)
      const endReached = newItems.length < count
		const canContinue = cursorAware
			? !!result.nextCursor
			: !endReached && (newTotal === 0 || newItems.length < newTotal)
		hasMoreRef.current = canContinue
		setHasMore(canContinue)
      setItems(newItems)
    } catch (err) {
      if (reqId === latestReqRef.current) setError(err?.message || 'Failed to refresh results')
    }
    finally {
      if (reloadReqRef.current === reqId) reloadingRef.current = false
      endRequest(reqId)
		if (reqId === latestReqRef.current) setTimeout(rearmSentinel, 0)
    }
  }, [pageSize, rearmSentinel])

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
      const direction = sortDesc ? -1 : 1
      merged.sort((a, b) => {
        const byTimestamp = String(a.timestamp || '').localeCompare(String(b.timestamp || ''))
        if (byTimestamp !== 0) return direction * byTimestamp
        return direction * (Number(a.id) - Number(b.id))
      })
      return merged
    })
    // Do not adjust `total` here: backend total already accounts for these rows.
    // A subsequent refresh/reset will reconcile counts precisely.
  }, [])

	const patchById = useCallback((updates) => {
		if (!Array.isArray(updates) || updates.length === 0) return
		const patches = new Map()
		for (const update of updates) {
			const patch = update?.score
			if (!patch) continue
			for (const id of update.packet_ids || []) patches.set(Number(id), patch)
		}
		if (patches.size === 0) return
		setItems((prev) => prev.map((item) => {
			const patch = patches.get(Number(item.id))
			return patch ? { ...item, ...patch } : item
		}))
	}, [])

  return {
    items,
    total,
    loading,
    hasMore,
		totalExact,
		partial,
	error,
    sentinelRef: combinedSentinelRef,
    prepend,
		patchById,
    refresh,
    reset,
  }
}
