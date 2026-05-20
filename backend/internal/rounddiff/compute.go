package rounddiff

import (
	"regexp"
	"sort"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// Stats summarises a packet set per round (the small box on top of each
// service card in the UI).
type Stats struct {
	Total    int `json:"total"`
	Req      int `json:"req"`
	Res      int `json:"res"`
	Flagged  int `json:"flagged"`
	FlagIDs  int `json:"flagids"`
	Dropped  int `json:"dropped"`
}

// RouteDelta describes how the volume of a single route changed between A
// and B. routes that appear only in one round have either CountA or CountB
// equal to zero.
type RouteDelta struct {
	Key    string `json:"key"`
	CountA int    `json:"count_a"`
	CountB int    `json:"count_b"`
}

// NovelPacket is a packet from round B whose content tokens deviate from the
// content tokens of the same route in round A. score is the fraction of
// novel tokens over total tokens.
type NovelPacket struct {
	PacketID      int64          `json:"packet_id"`
	RouteKey      string         `json:"route_key"`
	Score         float64        `json:"score"`
	NovelTokens   []string       `json:"novel_tokens"`
	SuspicionTags []SuspicionTag `json:"suspicion_tags,omitempty"`
	Scope         string         `json:"scope"` // "body" | "url" | "header"
	Direction     string         `json:"direction,omitempty"`
	Preview       string         `json:"preview"`
	URL           string         `json:"url,omitempty"`
	Method        string         `json:"method,omitempty"`
	Status        int            `json:"status,omitempty"`
	TwinPacketID  int64          `json:"twin_packet_id,omitempty"`
	Diff          []DiffOp       `json:"diff,omitempty"`
}

// SuspiciousBucket aggregates every packet whose payload matches the same
// combination of suspicion tags. Always surfaced regardless of novelty so
// repeat attacks across rounds remain visible.
type SuspiciousBucket struct {
	Key     string         `json:"key"`     // human-readable bucket label
	Tags    []SuspicionTag `json:"tags"`
	Scope   string         `json:"scope"`
	Count   int            `json:"count"`
	Samples []SampleRef    `json:"samples"`
}

// SampleRef is just enough to let the frontend open the original packet.
type SampleRef struct {
	PacketID int64  `json:"packet_id"`
	URL      string `json:"url,omitempty"`
	Method   string `json:"method,omitempty"`
	Preview  string `json:"preview,omitempty"`
}

// Result is the full payload returned by the round-diff endpoint.
type Result struct {
	ServiceID      string             `json:"service_id"`
	ServiceName    string             `json:"service_name,omitempty"`
	RoundA         int                `json:"round_a"`
	RoundB         int                `json:"round_b"`
	StatsA         Stats              `json:"stats_a"`
	StatsB         Stats              `json:"stats_b"`
	NewRoutes      []RouteDelta       `json:"new_routes"`
	GoneRoutes     []RouteDelta       `json:"gone_routes"`
	ChangedRoutes  []RouteDelta       `json:"changed_routes"`
	NovelPackets   []NovelPacket      `json:"novel_packets"`
	Suspicious     []SuspiciousBucket `json:"suspicious_in_b"`
	PacketsScanned int                `json:"packets_scanned"`
	Truncated      bool               `json:"truncated"`
}

// Options controls compute behaviour.
type Options struct {
	TopK              int  // how many novel packets to return (default 24)
	IncludeDiff       bool // when true, attach diff ops to each novel packet
	MaxDiffTokensSide int  // safety cap on token count per side of the diff (default 1500)
	MaxNovelTokens    int  // cap on novel-tokens list per packet (default 12)
	MinScore          float64
}

// Compute does the actual work: takes the two round packet sets and returns
// the structured diff. Callers (the handler) are responsible for fetching
// the packets and applying the cache.
func Compute(roundA, roundB int, packetsA, packetsB []*sniffer.Packet, opts Options) Result {
	if opts.TopK <= 0 {
		opts.TopK = 24
	}
	if opts.MaxDiffTokensSide <= 0 {
		opts.MaxDiffTokensSide = 1500
	}
	if opts.MaxNovelTokens <= 0 {
		opts.MaxNovelTokens = 12
	}

	res := Result{
		RoundA:         roundA,
		RoundB:         roundB,
		StatsA:         computeStats(packetsA),
		StatsB:         computeStats(packetsB),
		PacketsScanned: len(packetsA) + len(packetsB),
	}

	// Bucket every packet by its normalised route key, separately per round.
	routesA := groupByRoute(packetsA)
	routesB := groupByRoute(packetsB)

	// Per-route token multisets — the corpus we test "novelty" against.
	corpusA := make(map[string]TokenMultiset, len(routesA))
	for k, pkts := range routesA {
		m := TokenMultiset{}
		for _, p := range pkts {
			m.Add(p.BodyString)
			m.Add(p.URL)
			for _, hv := range p.Headers {
				m.Add(hv)
			}
		}
		corpusA[k] = m
	}

	// Route deltas — same shape as the old UI but computed over the
	// canonical routeKey above (so /flag/12345 and /flag/67890 collapse).
	res.NewRoutes, res.GoneRoutes, res.ChangedRoutes = computeRouteDeltas(routesA, routesB)

	// Walk every B packet and score it against its route's corpus in A.
	type scored struct {
		p     *sniffer.Packet
		route string
		score float64
		toks  []string
		scope string
		body  string
	}
	cands := make([]scored, 0, len(packetsB))
	for _, p := range packetsB {
		route := routeKey(p)
		corpus := corpusA[route]
		if corpus == nil {
			// Route is brand new — every token is "novel"; use the route key
			// itself to avoid scoring against an empty corpus.
			corpus = TokenMultiset{}
		}
		// Prefer the body when present, fall back to URL, then headers.
		body, scope := pickBestPayload(p)
		if body == "" {
			continue
		}
		score, novel, total := NoveltyScore(corpus, body, opts.MaxNovelTokens)
		if total < 4 {
			continue // payloads too short to score meaningfully
		}
		if score < opts.MinScore {
			continue
		}
		cands = append(cands, scored{p: p, route: route, score: score, toks: novel, scope: scope, body: body})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].p.ID < cands[j].p.ID
	})

	limit := opts.TopK
	if limit > len(cands) {
		limit = len(cands)
	}
	for _, c := range cands[:limit] {
		np := NovelPacket{
			PacketID:      c.p.ID,
			RouteKey:      c.route,
			Score:         c.score,
			NovelTokens:   c.toks,
			SuspicionTags: SuspicionTags(c.body),
			Scope:         c.scope,
			Direction:     string(c.p.Direction),
			Preview:       stripNonPrintable(c.body, 320),
			URL:           c.p.URL,
			Method:        c.p.Method,
			Status:        c.p.Status,
		}
		if opts.IncludeDiff {
			twin, twinBody := pickTwin(routesA[c.route], c.p, c.body)
			if twin != nil {
				np.TwinPacketID = twin.ID
				bToks := Tokenize(c.body)
				aToks := Tokenize(twinBody)
				np.Diff = TokenDiff(aToks, bToks, opts.MaxDiffTokensSide)
			}
		}
		res.NovelPackets = append(res.NovelPackets, np)
	}

	// Suspicious bucket aggregation across round B regardless of novelty.
	res.Suspicious = buildSuspiciousBuckets(packetsB)

	return res
}

func computeStats(pkts []*sniffer.Packet) Stats {
	st := Stats{}
	for _, p := range pkts {
		st.Total++
		if p.Direction == sniffer.DirectionRequest {
			st.Req++
		} else if p.Direction == sniffer.DirectionResponse {
			st.Res++
		}
		if p.Flagged {
			st.Flagged++
		}
		if p.ContainsFlagID {
			st.FlagIDs++
		}
		for _, mr := range p.MatchedRules {
			if mr.Action == "drop" || mr.Action == "both" {
				st.Dropped++
				break
			}
		}
	}
	return st
}

var (
	uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	hexRE  = regexp.MustCompile(`[0-9a-f]{16,}`)
	numRE  = regexp.MustCompile(`\b\d+\b`)
)

// routeKey builds the canonical route identifier shared between A and B,
// mirroring the original frontend logic so /flag/12345 and /flag/67890
// collapse to the same bucket.
func routeKey(p *sniffer.Packet) string {
	head := p.Method
	if head == "" {
		if p.Status > 0 {
			head = "status:" + itoa(p.Status)
		} else if p.Direction != "" {
			head = string(p.Direction)
		} else {
			head = "packet"
		}
	}
	url := p.URL
	if url == "" {
		url = "(tcp)"
	}
	if i := strings.IndexByte(url, '?'); i >= 0 {
		url = url[:i]
	}
	url = uuidRE.ReplaceAllString(strings.ToLower(url), ":uuid")
	url = hexRE.ReplaceAllString(url, ":hex")
	url = numRE.ReplaceAllString(url, ":id")
	return head + " " + url
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func groupByRoute(pkts []*sniffer.Packet) map[string][]*sniffer.Packet {
	out := make(map[string][]*sniffer.Packet, 64)
	for _, p := range pkts {
		k := routeKey(p)
		out[k] = append(out[k], p)
	}
	return out
}

func computeRouteDeltas(a, b map[string][]*sniffer.Packet) (newR, gone, changed []RouteDelta) {
	keys := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}
	for k := range keys {
		ca, cb := len(a[k]), len(b[k])
		rd := RouteDelta{Key: k, CountA: ca, CountB: cb}
		switch {
		case ca == 0 && cb > 0:
			newR = append(newR, rd)
		case cb == 0 && ca > 0:
			gone = append(gone, rd)
		case ca != cb:
			changed = append(changed, rd)
		}
	}
	sort.SliceStable(newR, func(i, j int) bool { return newR[i].CountB > newR[j].CountB })
	sort.SliceStable(gone, func(i, j int) bool { return gone[i].CountA > gone[j].CountA })
	sort.SliceStable(changed, func(i, j int) bool {
		di := abs(changed[i].CountB - changed[i].CountA)
		dj := abs(changed[j].CountB - changed[j].CountA)
		return di > dj
	})
	if len(newR) > 16 {
		newR = newR[:16]
	}
	if len(gone) > 16 {
		gone = gone[:16]
	}
	if len(changed) > 16 {
		changed = changed[:16]
	}
	return
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// pickBestPayload returns the most useful payload for novelty scoring, with
// a label identifying where it came from (body / url / header).
func pickBestPayload(p *sniffer.Packet) (string, string) {
	if strings.TrimSpace(p.BodyString) != "" {
		return p.BodyString, "body"
	}
	if q := queryString(p.URL); q != "" {
		return q, "url"
	}
	if len(p.Headers) > 0 {
		// Skip uninformative headers.
		skip := map[string]bool{"date": true, "content-length": true, "connection": true, "keep-alive": true, "server": true}
		var b strings.Builder
		for k, v := range p.Headers {
			if skip[strings.ToLower(k)] {
				continue
			}
			b.WriteString(k)
			b.WriteByte(':')
			b.WriteString(v)
			b.WriteByte('\n')
		}
		if b.Len() > 0 {
			return b.String(), "header"
		}
	}
	return "", ""
}

func queryString(url string) string {
	i := strings.IndexByte(url, '?')
	if i < 0 || i == len(url)-1 {
		return ""
	}
	return url[i+1:]
}

// pickTwin selects the A-side packet from the same route whose body is the
// closest to the B-side body, using token-set Jaccard similarity. When the
// route has no A-side packets we return nil and an empty body — the caller
// renders the diff as a pure insertion.
func pickTwin(aPkts []*sniffer.Packet, b *sniffer.Packet, bBody string) (*sniffer.Packet, string) {
	if len(aPkts) == 0 {
		return nil, ""
	}
	bToks := tokenSet(bBody)
	var best *sniffer.Packet
	var bestBody string
	bestSim := -1.0
	for _, p := range aPkts {
		body, _ := pickBestPayload(p)
		if body == "" {
			continue
		}
		aToks := tokenSet(body)
		sim := jaccard(aToks, bToks)
		if sim > bestSim {
			bestSim = sim
			best = p
			bestBody = body
		}
	}
	if best == nil {
		// Fall back to first packet's body even if empty so the caller can
		// still produce a "this whole thing is new" diff.
		return aPkts[0], ""
	}
	return best, bestBody
}

func tokenSet(s string) map[string]struct{} {
	out := make(map[string]struct{}, 16)
	for _, t := range Tokenize(s) {
		out[t] = struct{}{}
	}
	return out
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func buildSuspiciousBuckets(pkts []*sniffer.Packet) []SuspiciousBucket {
	buckets := map[string]*SuspiciousBucket{}
	for _, p := range pkts {
		body, scope := pickBestPayload(p)
		if body == "" {
			continue
		}
		tags := SuspicionTags(body)
		if len(tags) == 0 {
			continue
		}
		key := scope + ":" + joinTags(tags)
		b := buckets[key]
		if b == nil {
			b = &SuspiciousBucket{
				Key:   key,
				Tags:  tags,
				Scope: scope,
			}
			buckets[key] = b
		}
		b.Count++
		if len(b.Samples) < 6 {
			b.Samples = append(b.Samples, SampleRef{
				PacketID: p.ID,
				URL:      p.URL,
				Method:   p.Method,
				Preview:  stripNonPrintable(body, 220),
			})
		}
	}
	out := make([]SuspiciousBucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, *b)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func joinTags(tags []SuspicionTag) string {
	parts := make([]string, len(tags))
	for i, t := range tags {
		parts[i] = string(t)
	}
	return strings.Join(parts, "+")
}
