package api

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/rounddiff"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// roundPacketLimit is the per-round safety cap when fetching packets for the
// diff. Set high enough to cover even very chatty A/D services.
const roundPacketLimit = 10000

// fetchRoundPackets returns all packets for the (service, round) tuple. We
// push the time-range to SQL when the poller has competition timing
// configured (so it uses the timestamp index); otherwise we fall back to the
// DSL "round == N" filter which evaluates in Go.
// The second return value indicates whether the SQL limit was hit (i.e. the
// round had more packets than we could load).
func (s *Server) fetchRoundPackets(serviceID string, round int) ([]*sniffer.Packet, bool, error) {
	base := sniffer.PacketQuery{
		ServiceID: serviceID,
		SortOrder: "asc",
		Limit:     roundPacketLimit,
	}
	byID := make(map[int64]*sniffer.Packet, roundPacketLimit)
	truncated := false
	run := func(q sniffer.PacketQuery) error {
		pkts, total, err := s.packetStore.Query(q)
		if err != nil {
			return err
		}
		s.annotateRounds(pkts)
		for _, p := range pkts {
			if p.Round == round || p.FlagIDRound == round {
				byID[p.ID] = p
			}
		}
		if len(pkts) >= roundPacketLimit || total > roundPacketLimit {
			truncated = true
		}
		return nil
	}

	usedTimeBounds := false
	if s.flagIDPoller != nil {
		if start, end, ok := s.flagIDPoller.RoundBounds(round); ok {
			q := base
			q.TimeFrom = &start
			q.TimeTo = &end
			if err := run(q); err != nil {
				return nil, false, err
			}
			usedTimeBounds = true
		}
	}

	// Historical rows carry the persisted scanner round even if the current
	// competition-start config changed later. Union it with the timestamp
	// window so very old rounds do not disappear from round-diff.
	qFlagRound := base
	qFlagRound.FlagIDRound = &round
	if err := run(qFlagRound); err != nil {
		return nil, false, err
	}

	if !usedTimeBounds && len(byID) == 0 {
		q := base
		q.Q = "round == " + strconv.Itoa(round)
		if err := run(q); err != nil {
			return nil, false, err
		}
	}

	pkts := make([]*sniffer.Packet, 0, len(byID))
	for _, p := range byID {
		pkts = append(pkts, p)
	}
	sort.SliceStable(pkts, func(i, j int) bool {
		if pkts[i].Timestamp.Equal(pkts[j].Timestamp) {
			return pkts[i].ID < pkts[j].ID
		}
		return pkts[i].Timestamp.Before(pkts[j].Timestamp)
	})
	if len(pkts) > roundPacketLimit {
		pkts = pkts[:roundPacketLimit]
		truncated = true
	}
	return pkts, truncated, nil
}

func (s *Server) handleRoundDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	params := r.URL.Query()
	serviceID := params.Get("service_id")
	if serviceID == "" {
		http.Error(w, "service_id is required", http.StatusBadRequest)
		return
	}
	if _, ok := s.store.GetService(serviceID); !ok {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	roundA, err := strconv.Atoi(params.Get("round_a"))
	if err != nil || roundA < 1 {
		http.Error(w, "round_a must be a positive integer", http.StatusBadRequest)
		return
	}
	roundB, err := strconv.Atoi(params.Get("round_b"))
	if err != nil || roundB < 1 {
		http.Error(w, "round_b must be a positive integer", http.StatusBadRequest)
		return
	}

	topK := 24
	if v := params.Get("top_k"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			topK = n
		}
	}
	includeDiff := true
	if v := params.Get("include_diff"); v == "0" || v == "false" {
		includeDiff = false
	}

	cacheKey := rounddiff.CacheKey{
		ServiceID:   serviceID,
		RoundA:      roundA,
		RoundB:      roundB,
		TopK:        topK,
		IncludeDiff: includeDiff,
	}

	// Cache only rounds the scoreboard has fully moved past. Open/current
	// rounds can still receive packets, so cached empty results would hide
	// captures that arrive later.
	currentRound := 0
	if s.flagIDPoller != nil {
		currentRound = s.flagIDPoller.RoundForTime(time.Now())
		if currentRound == 0 {
			currentRound = s.flagIDPoller.CurrentRound()
		}
	}
	bothClosed := currentRound > 0 && roundA < currentRound && roundB < currentRound

	// Honour If-None-Match for the cached result so the frontend can poll
	// the same diff cheaply.
	etag := `"` + cacheKey.String() + `"`
	if bothClosed && s.roundDiffCache != nil {
		if cached := s.roundDiffCache.Get(cacheKey); cached != nil {
			if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("X-Round-Diff-Cache", "hit")
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

	start := time.Now()
	packetsA, truncA, err := s.fetchRoundPackets(serviceID, roundA)
	if err != nil {
		http.Error(w, "fetch round_a: "+err.Error(), http.StatusInternalServerError)
		return
	}
	packetsB, truncB, err := s.fetchRoundPackets(serviceID, roundB)
	if err != nil {
		http.Error(w, "fetch round_b: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := rounddiff.Compute(roundA, roundB, packetsA, packetsB, rounddiff.Options{
		TopK:        topK,
		IncludeDiff: includeDiff,
	})
	result.ServiceID = serviceID
	if svc, ok := s.store.GetService(serviceID); ok {
		result.ServiceName = svc.Name
	}
	if truncA || truncB {
		result.Truncated = true
	}

	if bothClosed && s.roundDiffCache != nil {
		s.roundDiffCache.Put(cacheKey, &result)
	}

	w.Header().Set("ETag", etag)
	cacheState := "miss"
	if !bothClosed {
		// Surfaced in DevTools so it's obvious why the same query keeps
		// recomputing: the round is still open.
		cacheState = "bypass-open-round"
	}
	w.Header().Set("X-Round-Diff-Cache", cacheState)
	w.Header().Set("X-Round-Diff-Compute-Ms", strconv.FormatInt(time.Since(start).Milliseconds(), 10))
	writeJSON(w, http.StatusOK, result)
}
