package flow

type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionAlert   Decision = "alert"
	DecisionDrop    Decision = "drop"
	DecisionRewrite Decision = "rewrite"
)

type Outcome string

const (
	OutcomeForwarded Outcome = "forwarded"
	OutcomeDropped   Outcome = "dropped"
	OutcomeRewritten Outcome = "rewritten"
	OutcomeFailed    Outcome = "failed"
	OutcomeWouldDrop Outcome = "would_drop"
)

// Verdict separates the requested policy decision from what the data plane
// actually applied. This prevents a response-side drop match from being
// reported as traffic that was really blocked.
type Verdict struct {
	Decision Decision `json:"decision"`
	Outcome  Outcome  `json:"outcome"`
	Phase    string   `json:"phase"`
	Applied  bool     `json:"applied"`
	RuleIDs  []string `json:"rule_ids,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func Forwarded(phase string) Verdict {
	return Verdict{Decision: DecisionAllow, Outcome: OutcomeForwarded, Phase: phase, Applied: true}
}
