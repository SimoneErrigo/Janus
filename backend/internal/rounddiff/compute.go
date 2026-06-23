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
	Total   int `json:"total"`
	Req     int `json:"req"`
	Res     int `json:"res"`
	Flagged int `json:"flagged"`
	FlagIDs int `json:"flagids"`
	Dropped int `json:"dropped"`
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
	ChangeFields  []string       `json:"change_fields,omitempty"`
	FieldDiffs    []FieldDiff    `json:"field_diffs,omitempty"`
}

// FieldDiff is the visual, field-level difference between a packet in round A
// and its closest packet in round B. It is intentionally generic: it does not
// depend on attack presets, only on captured packet contents.
type FieldDiff struct {
	Field     string   `json:"field"`
	Label     string   `json:"label"`
	Diff      []DiffOp `json:"diff,omitempty"`
	BeforeLen int      `json:"before_len,omitempty"`
	AfterLen  int      `json:"after_len,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// SuspiciousBucket aggregates every packet whose payload matches the same
// combination of suspicion tags. Always surfaced regardless of novelty so
// repeat attacks across rounds remain visible.
type SuspiciousBucket struct {
	Key     string         `json:"key"` // human-readable bucket label
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
	MaxFieldChars     int  // cap per side for visual field diffs (default 12000)
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
	if opts.MaxFieldChars <= 0 {
		opts.MaxFieldChars = 12000
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
	kindsA := groupByKind(packetsA)

	// Per-route token multisets — the corpus we test "novelty" against.
	corpusA := make(map[string]TokenMultiset, len(routesA))
	for k, pkts := range routesA {
		m := TokenMultiset{}
		for _, p := range pkts {
			m.Add(packetNoveltyText(p))
		}
		corpusA[k] = m
	}

	// Route deltas — same shape as the old UI but computed over the
	// canonical routeKey above (so /flag/12345 and /flag/67890 collapse).
	res.NewRoutes, res.GoneRoutes, res.ChangedRoutes = computeRouteDeltas(routesA, routesB)

	// Cache the A-side comparable text + token counts once, and a per-route set
	// of exact comparable texts. Twin matching reuses the counts (instead of
	// re-tokenizing every A packet for every B packet), and the exact set powers
	// the unchanged-packet fast path below.
	aCounts := make(map[*sniffer.Packet]map[string]int, len(packetsA))
	aExactByRoute := make(map[string]map[string]struct{}, len(routesA))
	for k, pkts := range routesA {
		set := make(map[string]struct{}, len(pkts))
		for _, p := range pkts {
			txt := comparablePacketText(p, true)
			aCounts[p] = exactTokenCounts(txt)
			set[txt] = struct{}{}
		}
		aExactByRoute[k] = set
	}
	// Twin matching can also fall back to the kind pool (packets not sharing the
	// exact route); make sure those A packets have cached counts too.
	for _, p := range packetsA {
		if _, ok := aCounts[p]; !ok {
			aCounts[p] = exactTokenCounts(comparablePacketText(p, true))
		}
	}

	// Walk every B packet and diff its captured contents against the closest
	// A-side packet. This is done in two phases: a cheap pass scores and filters
	// every B packet (no LCS), then the expensive field diffs are built only for
	// the top_k survivors. Suspicion presets are computed later as a secondary
	// view; this is the generic round-to-round packet-content comparison.
	type scored struct {
		p     *sniffer.Packet
		twin  *sniffer.Packet
		route string
		score float64
		toks  []string
	}
	cands := make([]scored, 0, len(packetsB))
	for _, p := range packetsB {
		route := routeKey(p)
		// Fast path: a verbatim copy of this packet already exists on the same
		// route in the baseline — it is unchanged, so there is nothing to show.
		// (Equivalent to the meaningful==false drop below, but without any work.)
		bText := comparablePacketText(p, true)
		if set := aExactByRoute[route]; set != nil {
			if _, ok := set[bText]; ok {
				continue
			}
		}
		corpus := corpusA[route]
		if corpus == nil {
			// Route is brand new — every token is "novel"; use an empty corpus
			// to avoid scoring against nothing.
			corpus = TokenMultiset{}
		}
		twin := pickTwinPacket(twinPool(routesA, kindsA, p), bText, aCounts)
		if _, meaningful := changedFields(twin, p); !meaningful {
			continue
		}
		novelScore, novel, _ := NoveltyScore(corpus, packetNoveltyText(p), opts.MaxNovelTokens)
		score := maxFloat(packetChangeScore(twin, p), novelScore)
		if score < opts.MinScore {
			continue
		}
		cands = append(cands, scored{p: p, twin: twin, route: route, score: score, toks: novel})
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
		// Phase 2: build the expensive field diffs and preview, only now.
		fieldDiffs, changeFields, _ := packetFieldDiffs(c.twin, c.p, opts)
		preview, scope := previewField(fieldDiffs, c.p)
		np := NovelPacket{
			PacketID:      c.p.ID,
			RouteKey:      c.route,
			Score:         c.score,
			NovelTokens:   c.toks,
			SuspicionTags: SuspicionTags(comparablePacketText(c.p, false)),
			Scope:         scope,
			Direction:     string(c.p.Direction),
			Preview:       stripNonPrintable(preview, 320),
			URL:           c.p.URL,
			Method:        c.p.Method,
			Status:        c.p.Status,
			ChangeFields:  changeFields,
		}
		if c.twin != nil {
			np.TwinPacketID = c.twin.ID
		}
		if opts.IncludeDiff {
			np.FieldDiffs = fieldDiffs
			for _, fd := range fieldDiffs {
				if fd.Field == "body" {
					np.Diff = fd.Diff
					break
				}
			}
			if len(np.Diff) == 0 && len(fieldDiffs) > 0 {
				np.Diff = fieldDiffs[0].Diff
			}
		}
		res.NovelPackets = append(res.NovelPackets, np)
	}

	// Suspicious bucket aggregation across round B regardless of novelty.
	res.Suspicious = buildSuspiciousBuckets(packetsB)

	// Force every slice on the wire to be a non-nil empty array. Go's JSON
	// encoder serialises a nil slice as `null`, and the frontend destructures
	// each field with `= []` defaults — but JS destructuring defaults only
	// trigger on `undefined`, not on `null`. A null here makes the UI throw
	// during render (e.g. `items.length` on RouteList), which without an
	// error boundary blanks the whole page. Cheap to fix, very confusing if
	// you don't know to look here.
	if res.NewRoutes == nil {
		res.NewRoutes = []RouteDelta{}
	}
	if res.GoneRoutes == nil {
		res.GoneRoutes = []RouteDelta{}
	}
	if res.ChangedRoutes == nil {
		res.ChangedRoutes = []RouteDelta{}
	}
	if res.NovelPackets == nil {
		res.NovelPackets = []NovelPacket{}
	}
	if res.Suspicious == nil {
		res.Suspicious = []SuspiciousBucket{}
	}

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

func groupByKind(pkts []*sniffer.Packet) map[string][]*sniffer.Packet {
	out := make(map[string][]*sniffer.Packet, 16)
	for _, p := range pkts {
		k := kindKey(p)
		out[k] = append(out[k], p)
	}
	return out
}

func kindKey(p *sniffer.Packet) string {
	if p == nil {
		return ""
	}
	parts := []string{p.Protocol, string(p.Direction)}
	if p.Method != "" {
		parts = append(parts, p.Method)
	}
	return strings.Join(parts, " ")
}

func twinPool(routes map[string][]*sniffer.Packet, kinds map[string][]*sniffer.Packet, p *sniffer.Packet) []*sniffer.Packet {
	if pkts := routes[routeKey(p)]; len(pkts) > 0 {
		return pkts
	}
	return kinds[kindKey(p)]
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

func packetFieldDiffs(a, b *sniffer.Packet, opts Options) ([]FieldDiff, []string, bool) {
	fields := []struct {
		name       string
		label      string
		before     string
		after      string
		meaningful bool
	}{
		{name: "url", label: "URL", before: requestLine(a), after: requestLine(b), meaningful: true},
		{name: "status", label: "Status", before: statusText(a), after: statusText(b), meaningful: true},
		{name: "headers", label: "Headers", before: headersText(a, false), after: headersText(b, false), meaningful: headersText(a, true) != headersText(b, true)},
		{name: "body", label: "Body", before: bodyText(a), after: bodyText(b), meaningful: true},
	}

	out := make([]FieldDiff, 0, len(fields))
	changed := make([]string, 0, len(fields))
	meaningfulChanged := false
	for _, f := range fields {
		if f.before == f.after {
			continue
		}
		before, after, truncated := truncatePair(f.before, f.after, opts.MaxFieldChars)
		out = append(out, FieldDiff{
			Field:     f.name,
			Label:     f.label,
			Diff:      TextDiff(before, after, opts.MaxDiffTokensSide),
			BeforeLen: len(f.before),
			AfterLen:  len(f.after),
			Truncated: truncated,
		})
		changed = append(changed, f.name)
		if f.meaningful {
			meaningfulChanged = true
		}
	}
	return out, changed, meaningfulChanged
}

func requestLine(p *sniffer.Packet) string {
	if p == nil {
		return ""
	}
	if p.Method == "" && p.URL == "" {
		return ""
	}
	if p.Method == "" {
		return p.URL
	}
	if p.URL == "" {
		return p.Method
	}
	return p.Method + " " + p.URL
}

func statusText(p *sniffer.Packet) string {
	if p == nil || p.Status == 0 {
		return ""
	}
	return itoa(p.Status)
}

func bodyText(p *sniffer.Packet) string {
	if p == nil {
		return ""
	}
	return p.BodyString
}

var noisyHeaderNames = map[string]bool{
	"connection":        true,
	"content-length":    true,
	"date":              true,
	"keep-alive":        true,
	"server":            true,
	"transfer-encoding": true,
}

func headersText(p *sniffer.Packet, significantOnly bool) string {
	if p == nil || len(p.Headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p.Headers))
	for k := range p.Headers {
		if significantOnly && noisyHeaderNames[strings.ToLower(k)] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(p.Headers[k])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

func truncatePair(a, b string, maxChars int) (string, string, bool) {
	if maxChars <= 0 {
		return a, b, false
	}
	ta, aCut := truncateString(a, maxChars)
	tb, bCut := truncateString(b, maxChars)
	return ta, tb, aCut || bCut
}

func truncateString(s string, maxChars int) (string, bool) {
	if len(s) <= maxChars {
		return s, false
	}
	if maxChars <= len("…") {
		return "…", true
	}
	return s[:maxChars-len("…")] + "…", true
}

func previewField(diffs []FieldDiff, p *sniffer.Packet) (string, string) {
	preferred := []string{"body", "url", "headers", "status"}
	for _, want := range preferred {
		for _, fd := range diffs {
			if fd.Field == want {
				switch want {
				case "body":
					return bodyText(p), "body"
				case "url":
					return requestLine(p), "url"
				case "headers":
					return headersText(p, false), "header"
				case "status":
					return statusText(p), "status"
				}
			}
		}
	}
	body, scope := pickBestPayload(p)
	return body, scope
}

func comparablePacketText(p *sniffer.Packet, significantHeadersOnly bool) string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	if v := requestLine(p); v != "" {
		b.WriteString("url ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	if v := statusText(p); v != "" {
		b.WriteString("status ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	if v := headersText(p, significantHeadersOnly); v != "" {
		b.WriteString("headers\n")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	if p.BodyString != "" {
		b.WriteString("body\n")
		b.WriteString(p.BodyString)
	}
	return b.String()
}

func packetNoveltyText(p *sniffer.Packet) string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	if v := requestLine(p); v != "" {
		parts = append(parts, v)
	}
	if v := statusText(p); v != "" {
		parts = append(parts, v)
	}
	if v := headersText(p, true); v != "" {
		parts = append(parts, v)
	}
	if p.BodyString != "" {
		parts = append(parts, p.BodyString)
	}
	return strings.Join(parts, "\n")
}

func packetChangeScore(a, b *sniffer.Packet) float64 {
	if a == nil {
		if comparablePacketText(b, true) == "" {
			return 0
		}
		return 1
	}
	weighted := []struct {
		weight float64
		before string
		after  string
	}{
		{0.25, requestLine(a), requestLine(b)},
		{0.05, statusText(a), statusText(b)},
		{0.15, headersText(a, true), headersText(b, true)},
		{0.55, bodyText(a), bodyText(b)},
	}
	var score float64
	for _, f := range weighted {
		score += f.weight * exactChangeScore(f.before, f.after)
	}
	return score
}

// pickTwinPacket selects the A-side packet whose significant content is most
// similar to b. bText is b's precomputed comparable text and aCounts holds the
// precomputed token counts for every A packet, so the inner loop does no
// tokenisation work.
func pickTwinPacket(aPkts []*sniffer.Packet, bText string, aCounts map[*sniffer.Packet]map[string]int) *sniffer.Packet {
	if len(aPkts) == 0 {
		return nil
	}
	bCounts := exactTokenCounts(bText)
	var best *sniffer.Packet
	bestSim := -1.0
	for _, p := range aPkts {
		sim := exactSimilarityCounts(aCounts[p], bCounts)
		if sim > bestSim {
			bestSim = sim
			best = p
		}
	}
	if best == nil {
		return aPkts[0]
	}
	return best
}

// exactSimilarityCounts is the token-multiset Jaccard similarity over two
// precomputed token-count maps.
func exactSimilarityCounts(ta, tb map[string]int) float64 {
	if len(ta) == 0 && len(tb) == 0 {
		return 1
	}
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	common := 0
	totalA := 0
	totalB := 0
	for tok, ca := range ta {
		totalA += ca
		if cb := tb[tok]; cb > 0 {
			if ca < cb {
				common += ca
			} else {
				common += cb
			}
		}
	}
	for _, cb := range tb {
		totalB += cb
	}
	union := totalA + totalB - common
	if union <= 0 {
		return 0
	}
	return float64(common) / float64(union)
}

// changedFields reports which packet fields differ between a (baseline twin)
// and b, plus whether any *meaningful* change occurred. It is the cheap
// counterpart of packetFieldDiffs: it does only string-equality checks and
// never builds an LCS diff, so it can run over every B packet. The field set,
// ordering, and "meaningful" semantics mirror packetFieldDiffs exactly.
func changedFields(a, b *sniffer.Packet) ([]string, bool) {
	fields := []struct {
		name       string
		before     string
		after      string
		meaningful bool
	}{
		{"url", requestLine(a), requestLine(b), true},
		{"status", statusText(a), statusText(b), true},
		{"headers", headersText(a, false), headersText(b, false), false},
		{"body", bodyText(a), bodyText(b), true},
	}
	changed := make([]string, 0, len(fields))
	meaningful := false
	for _, f := range fields {
		if f.before == f.after {
			continue
		}
		changed = append(changed, f.name)
		if f.name == "headers" {
			if headersText(a, true) != headersText(b, true) {
				meaningful = true
			}
		} else if f.meaningful {
			meaningful = true
		}
	}
	return changed, meaningful
}

func exactChangeScore(a, b string) float64 {
	if a == b {
		return 0
	}
	ta := exactTokenCounts(a)
	tb := exactTokenCounts(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 1
	}
	common := 0
	totalA := 0
	totalB := 0
	for tok, ca := range ta {
		totalA += ca
		if cb := tb[tok]; cb > 0 {
			if ca < cb {
				common += ca
			} else {
				common += cb
			}
		}
	}
	for _, cb := range tb {
		totalB += cb
	}
	denom := totalA
	if totalB > denom {
		denom = totalB
	}
	if denom == 0 {
		return 1
	}
	score := float64(denom-common) / float64(denom)
	if score == 0 {
		return 0.02
	}
	return score
}

func exactTokenCounts(s string) map[string]int {
	out := make(map[string]int, 16)
	for _, tok := range VisualTokenize(s) {
		if strings.TrimSpace(tok) == "" {
			continue
		}
		out[tok]++
	}
	return out
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func queryString(url string) string {
	i := strings.IndexByte(url, '?')
	if i < 0 || i == len(url)-1 {
		return ""
	}
	return url[i+1:]
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
