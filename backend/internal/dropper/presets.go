package dropper

// PresetRule is a single rule template within a preset category.
type PresetRule struct {
	Name    string    `json:"name"`
	Type    MatchType `json:"type"`
	Scope   Scope     `json:"scope"`
	Pattern string    `json:"pattern"`
	Action  Action    `json:"action"`
}

// PresetCategory groups related attack patterns.
type PresetCategory struct {
	Name  string       `json:"name"`
	Icon  string       `json:"icon"`
	Rules []PresetRule `json:"rules"`
}

// GetPresets returns all built-in attack preset categories.
func GetPresets() []PresetCategory {
	return []PresetCategory{
		{
			Name: "SQL Injection",
			Icon: "\U0001F5C3",
			Rules: []PresetRule{
				{Name: "SQLi: UNION SELECT", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)union\s+(all\s+)?select\b`, Action: ActionBoth},
				{Name: "SQLi: OR/AND bypass", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)['"]\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`, Action: ActionBoth},
				{Name: "SQLi: comment terminator", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(?:\s|'|")(--|#|\/\*|%2d%2d|%23)`, Action: ActionAlert},
				{Name: "SQLi: SLEEP/BENCHMARK (blind)", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(`, Action: ActionBoth},
				{Name: "SQLi: stacked queries", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i);\s*(drop|alter|delete|update|insert|create)\s`, Action: ActionDrop},
				{Name: "SQLi: extractvalue/updatexml", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(extractvalue|updatexml|load_file|into\s+(out|dump)file)\s*\(`, Action: ActionBoth},
				{Name: "SQLi: SQLite specific", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(sqlite_version|sqlite_master|randomblob)\s*\(`, Action: ActionBoth},
				{Name: "SQLi: concatenation operator", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(\|\||\+)\s*\(?\s*select\b`, Action: ActionBoth},
			},
		},
		{
			Name: "XSS",
			Icon: "\U0001F310",
			Rules: []PresetRule{
				{Name: "XSS: script tag", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)<\s*script[\s>]`, Action: ActionBoth},
				{Name: "XSS: event handler", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\bon(error|load|click|mouseover|focus|blur|submit)\s*=`, Action: ActionAlert},
				{Name: "XSS: javascript: URI", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)javascript\s*:`, Action: ActionBoth},
				{Name: "XSS: img/svg/iframe injection", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)<\s*(img|svg|iframe|embed|object)[\s/]`, Action: ActionAlert},
			},
		},
		{
			Name: "Path Traversal",
			Icon: "\U0001F4C2",
			Rules: []PresetRule{
				{Name: "PathTrav: dot-dot-slash", Type: MatchRegex, Scope: ScopeURL, Pattern: `(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f)`, Action: ActionDrop},
				{Name: "PathTrav: /etc/passwd", Type: MatchString, Scope: ScopeURL, Pattern: "/etc/passwd", Action: ActionDrop},
				{Name: "PathTrav: /etc/shadow", Type: MatchString, Scope: ScopeURL, Pattern: "/etc/shadow", Action: ActionDrop},
				{Name: "PathTrav: /proc/self", Type: MatchString, Scope: ScopeURL, Pattern: "/proc/self", Action: ActionDrop},
				{Name: "PathTrav: Windows paths", Type: MatchRegex, Scope: ScopeURL, Pattern: `(?i)(\\windows\\|\\system32\\|c:\\)`, Action: ActionDrop},
				{Name: "PathTrav: null byte", Type: MatchRegex, Scope: ScopeURL, Pattern: `(%00|\\x00|\\0)`, Action: ActionDrop},
			},
		},
		{
			Name: "Command Injection",
			Icon: "\u26A1",
			Rules: []PresetRule{
				{Name: "CMDi: shell metacharacters", Type: MatchRegex, Scope: ScopeBody, Pattern: `(;|\||\&\&|\|\||` + "`" + `|\$\()[\s]*\w`, Action: ActionBoth},
				{Name: "CMDi: common commands", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\b(cat|ls|id|whoami|wget|curl|nc|ncat|bash|sh|python|perl|ruby|php)\s`, Action: ActionAlert},
				{Name: "CMDi: reverse shell", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(bash\s+-i|/dev/tcp/|nc\s+-[el]|mkfifo|\bexec\s+\d+)`, Action: ActionDrop},
				{Name: "CMDi: encoded newline", Type: MatchRegex, Scope: ScopeBody, Pattern: `(%0a|%0d|\\n|\\r)`, Action: ActionAlert},
				{Name: "CMDi: IFS bypass", Type: MatchRegex, Scope: ScopeBody, Pattern: `(\$IFS|\$\{IFS\}|\$\(\(|\{[a-z]+,)`, Action: ActionDrop},
			},
		},
		{
			Name: "XXE",
			Icon: "\U0001F4C4",
			Rules: []PresetRule{
				{Name: "XXE: DOCTYPE", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)<!\s*DOCTYPE`, Action: ActionBoth},
				{Name: "XXE: ENTITY", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)<!\s*ENTITY`, Action: ActionDrop},
				{Name: "XXE: SYSTEM file:", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)SYSTEM\s+["']file:`, Action: ActionDrop},
				{Name: "XXE: SYSTEM http:", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)SYSTEM\s+["']https?:`, Action: ActionDrop},
				{Name: "XXE: CDATA", Type: MatchString, Scope: ScopeBody, Pattern: "<![CDATA[", Action: ActionAlert},
			},
		},
		{
			Name: "SSTI",
			Icon: "\U0001F527",
			Rules: []PresetRule{
				{Name: "SSTI: Jinja2/Twig {{ }}", Type: MatchRegex, Scope: ScopeBody, Pattern: `\{\{.*\}\}`, Action: ActionAlert},
				{Name: "SSTI: Jinja2 {% %}", Type: MatchRegex, Scope: ScopeBody, Pattern: `\{%.*%\}`, Action: ActionAlert},
				{Name: "SSTI: ${...} expression", Type: MatchRegex, Scope: ScopeBody, Pattern: `\$\{[^}]+\}`, Action: ActionAlert},
				{Name: "SSTI: Jinja2 class chain", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(__class__|__mro__|__subclasses__|__builtins__|__import__)`, Action: ActionDrop},
				{Name: "SSTI: ERB/EJS <%= %>", Type: MatchRegex, Scope: ScopeBody, Pattern: `<%[=\s]`, Action: ActionAlert},
			},
		},
		{
			Name: "PHP",
			Icon: "\U0001F418",
			Rules: []PresetRule{
				{Name: "PHP: code execution", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(`, Action: ActionDrop},
				{Name: "PHP: eval/assert", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\b(eval|assert|preg_replace.*e)\s*\(`, Action: ActionDrop},
				{Name: "PHP: file inclusion", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\b(include|require|include_once|require_once)\s*\(`, Action: ActionAlert},
				{Name: "PHP: wrappers", Type: MatchRegex, Scope: ScopeURL, Pattern: `(?i)(php://filter|php://input|data://text|expect://)`, Action: ActionDrop},
				{Name: "PHP: deserialization", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(O:\d+:"|a:\d+:\{|unserialize\s*\()`, Action: ActionBoth},
				{Name: "PHP: tag injection", Type: MatchRegex, Scope: ScopeBody, Pattern: `<\?php`, Action: ActionDrop},
			},
		},
		{
			Name: "Python",
			Icon: "\U0001F40D",
			Rules: []PresetRule{
				{Name: "Python: os/subprocess", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(os\.(system|popen)|subprocess\.(call|run|Popen|check_output))`, Action: ActionDrop},
				{Name: "Python: eval/exec", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\b(eval|exec|compile)\s*\(`, Action: ActionBoth},
				{Name: "Python: __import__", Type: MatchRegex, Scope: ScopeBody, Pattern: `__import__\s*\(`, Action: ActionDrop},
				{Name: "Python: pickle/marshal", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(pickle\.(loads|load)|marshal\.loads|yaml\.load)`, Action: ActionDrop},
				{Name: "Python: dunder chain", Type: MatchRegex, Scope: ScopeBody, Pattern: `(__class__|__subclasses__|__globals__|__builtins__)`, Action: ActionDrop},
			},
		},
		{
			Name: "Node.js",
			Icon: "\U0001F7E9",
			Rules: []PresetRule{
				{Name: "Node: child_process", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(child_process|require\s*\(\s*["']child)`, Action: ActionDrop},
				{Name: "Node: eval/Function", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(\beval\s*\(|new\s+Function\s*\()`, Action: ActionBoth},
				{Name: "Node: prototype pollution", Type: MatchRegex, Scope: ScopeBody, Pattern: `(__proto__|constructor\s*\.\s*prototype)`, Action: ActionDrop},
				{Name: "Node: require injection", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)require\s*\(\s*['"]\s*(fs|net|http|child)`, Action: ActionDrop},
			},
		},
		{
			Name: "Flag Exfiltration",
			Icon: "\U0001F6A9",
			Rules: []PresetRule{
				{Name: "Exfil: curl/wget out", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(curl|wget)\s+https?://(?!10\.)`, Action: ActionDrop},
				{Name: "Exfil: nc/ncat outbound", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(nc|ncat)\s+\S+\s+\d{2,5}`, Action: ActionDrop},
				{Name: "Exfil: DNS exfil", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(dig|nslookup|host)\s+\S+\.\S+`, Action: ActionAlert},
				{Name: "Exfil: base64 pipe", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)base64[\s|]+`, Action: ActionAlert},
			},
		},
		{
			Name: "SSRF",
			Icon: "\U0001F310",
			Rules: []PresetRule{
				{Name: "SSRF: internal IP (10.x)", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(https?://|url=|uri=|path=|redirect=|next=|target=|dest=)10\.\d{1,3}\.\d{1,3}\.\d{1,3}`, Action: ActionAlert},
				{Name: "SSRF: localhost/127.0.0.1", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(https?://)(localhost|127\.0\.0\.1|0\.0\.0\.0|0x7f)`, Action: ActionDrop},
				{Name: "SSRF: metadata endpoint", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(169\.254\.169\.254|metadata\.google|metadata\.aws)`, Action: ActionDrop},
				{Name: "SSRF: file:// scheme", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)file://`, Action: ActionDrop},
				{Name: "SSRF: gopher:// scheme", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)gopher://`, Action: ActionDrop},
				{Name: "SSRF: dict:// scheme", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)dict://`, Action: ActionDrop},
			},
		},
		// {
		// 	Name: "LDAP/JNDI Injection",
		// 	Icon: "\U0001F4E1",
		// 	Rules: []PresetRule{
		// 		{Name: "JNDI: Log4Shell lookup", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\$\{jndi:(ldap|rmi|dns|iiop)://`, Action: ActionDrop},
		// 		{Name: "JNDI: nested bypass", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\$\{[^}]*\$\{[^}]*jndi`, Action: ActionDrop},
		// 		{Name: "JNDI: header injection", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)\$\{jndi:`, Action: ActionDrop},
		// 		{Name: "LDAP: filter injection", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(\||\&)\s*\([a-zA-Z]+=\*\)`, Action: ActionAlert},
		// 	},
		// },
		{
			Name: "Deserialization",
			Icon: "\U0001F4E6",
			Rules: []PresetRule{
				{Name: "Java: serialized object magic", Type: MatchBytes, Scope: ScopeRaw, Pattern: `aced0005`, Action: ActionBoth},
				{Name: "Java: common gadgets", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(CommonsCollections|InvokerTransformer|TemplatesImpl|JRMPClient|BeanShell|Groovy)`, Action: ActionDrop},
				{Name: "Python: pickle header", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(c__builtin__|cposix|csystem|cos\nsystem|creduce)`, Action: ActionDrop},
				{Name: "Ruby: Marshal.load", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(Marshal\.load|YAML\.load|ERB\.new)`, Action: ActionAlert},
				{Name: ".NET: ObjectStateFormatter", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(ObjectStateFormatter|LosFormatter|BinaryFormatter|TypeNameHandling)`, Action: ActionDrop},
			},
		},
		{
			Name: "Auth Bypass",
			Icon: "\U0001F511",
			Rules: []PresetRule{
				{Name: "Auth: JWT none algorithm", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)"alg"\s*:\s*"none"`, Action: ActionDrop},
				{Name: "Auth: JWT alg confusion", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)"alg"\s*:\s*"(HS|RS|ES|PS)(256|384|512)".*"typ"\s*:\s*"JWT"|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.$`, Action: ActionAlert},
				{Name: "Auth: admin=true param", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(admin|is_admin|isAdmin|role)\s*[=:]\s*(true|1|admin|root)`, Action: ActionAlert},
				{Name: "Auth: mass assignment", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(is_admin|isAdmin|role|privilege|permission)\s*["']?\s*[=:]\s*["']?(admin|root|superuser|1|true)`, Action: ActionAlert},
			},
		},
		{
			Name: "NoSQL Injection",
			Icon: "\U0001F343",
			Rules: []PresetRule{
				{Name: "NoSQLi: $gt/$ne operator", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(\$gt|\$ne|\$lt|\$gte|\$lte|\$nin|\$in|\$exists|\$regex)\s*[:\]]`, Action: ActionBoth},
				{Name: "NoSQLi: $where JS", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\$where\s*[=:]\s*["']`, Action: ActionDrop},
				{Name: "NoSQLi: MongoDB $or bypass", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)\$or\s*[:\[]\s*\[?\s*\{`, Action: ActionBoth},
				{Name: "NoSQLi: regex DoS", Type: MatchRegex, Scope: ScopeBody, Pattern: `\$regex.*(\.\*){3,}`, Action: ActionDrop},
			},
		},
		{
			Name: "IDOR / Access Control",
			Icon: "\U0001F50D",
			Rules: []PresetRule{
				{Name: "IDOR: sequential ID scan", Type: MatchRegex, Scope: ScopeURL, Pattern: `(?i)/(user|profile|account|order|flag|admin)/\d{1,6}$`, Action: ActionAlert},
				{Name: "IDOR: UUID enumeration", Type: MatchRegex, Scope: ScopeURL, Pattern: `(?i)/(user|profile|account|flag)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, Action: ActionAlert},
				{Name: "Access: /admin path", Type: MatchRegex, Scope: ScopeURL, Pattern: `(?i)^/(admin|debug|internal|_debug|swagger|graphql)(/|$)`, Action: ActionAlert},
				{Name: "Access: HTTP method override", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)(X-HTTP-Method-Override|X-Method-Override|X-HTTP-Method)\s*:\s*(PUT|DELETE|PATCH)`, Action: ActionAlert},
			},
		},
		{
			Name: "Web Shell / Backdoor",
			Icon: "\U0001F41A",
			Rules: []PresetRule{
				{Name: "Shell: webshell keywords", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(c99shell|r57shell|wso\s|b374k|weevely|phpspy|filesman|p0wny)`, Action: ActionDrop},
				{Name: "Shell: cmd/command param", Type: MatchRegex, Scope: ScopeURL, Pattern: `(?i)[?&](cmd|command|exec|execute|run|shell|code)=`, Action: ActionBoth},
				{Name: "Shell: base64 decode+exec", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)(base64_decode|atob)\s*\([^)]+\)\s*[;)]\s*(eval|exec|system|passthru)`, Action: ActionDrop},
				{Name: "Shell: suspicious User-Agent", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)User-Agent:\s*(sqlmap|nikto|nmap|dirbuster|gobuster|ffuf|nuclei|hydra|burp)`, Action: ActionBoth},
			},
		},
		{
			Name: "File Upload",
			Icon: "\U0001F4CE",
			Rules: []PresetRule{
				{Name: "Upload: PHP in filename", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)filename=["']?[^"']*\.(php[0-9]?|phtml|phar|inc)\b`, Action: ActionDrop},
				{Name: "Upload: double extension", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)filename=["']?[^"']*\.(jpg|png|gif|pdf)\.(php|asp|jsp|py|rb|pl|cgi)\b`, Action: ActionDrop},
				{Name: "Upload: null byte in name", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)filename=["']?[^"']*(%00|\\x00)[^"']*\.(php|asp|jsp)\b`, Action: ActionDrop},
				{Name: "Upload: SVG with script", Type: MatchRegex, Scope: ScopeBody, Pattern: `(?i)<svg[^>]*>.*<script`, Action: ActionDrop},
				{Name: "Upload: .htaccess", Type: MatchRegex, Scope: ScopeHeader, Pattern: `(?i)filename=["']?\.htaccess`, Action: ActionDrop},
			},
		},
	}
}
