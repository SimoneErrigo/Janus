package rounddiff

import "regexp"

// SuspicionTag categorises a payload as matching a known attack pattern.
// Keep in sync with backend/internal/dropper/presets.go and the matching
// rules on the frontend so the UI labels stay consistent.
type SuspicionTag string

const (
	TagSQLi       SuspicionTag = "sqli"
	TagSQLiSyntax SuspicionTag = "sqli-syntax"
	TagXSS        SuspicionTag = "xss"
	TagCMDi       SuspicionTag = "cmdi"
	TagPath       SuspicionTag = "path"
	TagSSTI       SuspicionTag = "ssti"
	TagNoSQLi     SuspicionTag = "nosqli"
	TagSSRF       SuspicionTag = "ssrf"
	TagXXE        SuspicionTag = "xxe"
	TagDeser      SuspicionTag = "deser"
	TagEnc        SuspicionTag = "enc"
	TagPHP        SuspicionTag = "php"
	TagExfil      SuspicionTag = "exfil"
)

type suspicionPattern struct {
	tag SuspicionTag
	re  *regexp.Regexp
}

var suspicionPatterns = []suspicionPattern{
	{TagSQLi, regexp.MustCompile(`(?i)(?:union\s+(?:all\s+)?select|\bselect\b[\s\S]{0,80}\bfrom\b|string_agg\s*\(|extractvalue\s*\(|updatexml\s*\(|sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|sqlite_version|sqlite_master|into\s+(?:out|dump)file|load_file\s*\()`)},
	// A plain C-style comment is common in source, CSS and documentation and
	// is not evidence of SQL injection. Keep only comments joined to SQL
	// operators/keywords (including MySQL executable comments).
	{TagSQLiSyntax, regexp.MustCompile(`(?i)(?:'|"|` + "`" + `)\s*(?:or|and)\s+['"` + "`" + `]?\d+['"` + "`" + `]?\s*=\s*['"` + "`" + `]?\d+|(?:^|[\s'")])--\s|/\*![\s\S]*?\*/|\b(?:union|select|or|and)\b\s*/\*[\s\S]{0,80}?\*/|/\*[\s\S]{0,80}?\*/\s*\b(?:union|select|or|and)\b|;\s*(?:drop|alter|delete|update|insert|create|truncate)\b|\|\|\s*\(?\s*select\b`)},
	{TagXSS, regexp.MustCompile(`(?i)<\s*(?:script|svg|iframe|img|object|embed|body|input)\b|\bon(?:error|load|click|mouseover|focus|blur|submit|toggle|animationend)\s*=|javascript\s*:`)},
	// `&&` / `||` only trigger when followed by a word char so SQL string
	// concatenation (`' || (SELECT …`) doesn't cross-tag as command injection.
	{TagCMDi, regexp.MustCompile(`(?i)\$\(|` + "`" + `[^` + "`" + `]{1,80}` + "`" + `|(?:&&|\|\|)\s*\w|\$\{IFS\}|\$IFS\b|\b(?:bash|sh|nc|ncat|wget|curl|whoami|mkfifo|chmod|chown)\s|/dev/tcp/`)},
	{TagPath, regexp.MustCompile(`(?i)(?:\.\.[/\\]){1,}|%2e%2e(?:%2f|%5c|/|\\)|/etc/(?:passwd|shadow|hosts)\b|/proc/self\b|c:\\windows\\|\\system32\\`)},
	{TagSSTI, regexp.MustCompile(`\{\{[^{}]*\}\}|\{%[^%]*%\}|<%[=\s][\s\S]*?%>|__class__|__subclasses__|__builtins__|__import__|__globals__|__mro__`)},
	{TagNoSQLi, regexp.MustCompile(`(?i)"\$(?:gt|ne|lt|gte|lte|nin|in|exists|regex|where|or)"\s*:|"\$or"\s*:\s*\[`)},
	{TagSSRF, regexp.MustCompile(`(?i)\bfile://|\bgopher://|\bdict://|\b169\.254\.169\.254\b|\b127\.0\.0\.1\b|metadata\.(?:google|aws)`)},
	{TagXXE, regexp.MustCompile(`(?i)<!\s*DOCTYPE\b|<!\s*ENTITY\b|SYSTEM\s+["'](?:file|https?):`)},
	{TagDeser, regexp.MustCompile(`(?i)aced0005|O:\d+:"|a:\d+:\{|CommonsCollections|InvokerTransformer|TemplatesImpl|TypeNameHandling|ObjectStateFormatter|BinaryFormatter`)},
	{TagEnc, regexp.MustCompile(`(?i)(?:%[0-9a-f]{2}){5,}|(?:\\x[0-9a-f]{2}){3,}|(?:\\u00[0-9a-f]{2}){3,}`)},
	{TagPHP, regexp.MustCompile(`(?i)<\?php\b|\b(?:eval|system|exec|passthru|shell_exec|popen|proc_open)\s*\(|php://(?:filter|input)`)},
	// RE2 has no lookahead, so we can't carve out internal IPs in one shot —
	// downstream code (or a follow-up regex) can post-filter if needed.
	{TagExfil, regexp.MustCompile(`(?i)(?:curl|wget)\s+https?://|base64\s*(?:-d|--decode)|\bnc\s+\S+\s+\d{2,5}`)},
}

// SuspicionTags returns the set of attack categories that match the given
// payload. The returned slice is sorted by the order of suspicionPatterns
// so identical payloads always produce the same tag sequence.
func SuspicionTags(s string) []SuspicionTag {
	if len(s) < 3 {
		return nil
	}
	var tags []SuspicionTag
	for _, p := range suspicionPatterns {
		if p.re.MatchString(s) {
			tags = append(tags, p.tag)
		}
	}
	return tags
}
