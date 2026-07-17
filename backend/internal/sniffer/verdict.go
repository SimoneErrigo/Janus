package sniffer

import flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"

// VerdictFor turns policy matches and the actual enforcement result into one
// authoritative verdict. enforceable is false at post-forward boundaries such
// as HTTP responses.
func VerdictFor(direction Direction, matches []MatchedRuleInfo, dropped, rewritten, enforceable bool) flowmodel.Verdict {
	ruleIDs := make([]string, 0, len(matches))
	hasDrop, hasAlert := false, false
	for _, match := range matches {
		ruleIDs = append(ruleIDs, match.ID)
		switch match.Action {
		case "drop":
			hasDrop = true
		case "both":
			hasDrop, hasAlert = true, true
		case "alert":
			hasAlert = true
		}
	}
	phase := string(direction)
	switch {
	case dropped:
		return flowmodel.Verdict{Decision: flowmodel.DecisionDrop, Outcome: flowmodel.OutcomeDropped, Phase: phase, Applied: true, RuleIDs: ruleIDs}
	case rewritten:
		return flowmodel.Verdict{Decision: flowmodel.DecisionRewrite, Outcome: flowmodel.OutcomeRewritten, Phase: phase, Applied: true, RuleIDs: ruleIDs}
	case hasDrop && !enforceable:
		return flowmodel.Verdict{Decision: flowmodel.DecisionDrop, Outcome: flowmodel.OutcomeWouldDrop, Phase: phase, Applied: false, RuleIDs: ruleIDs}
	case hasDrop:
		return flowmodel.Verdict{Decision: flowmodel.DecisionDrop, Outcome: flowmodel.OutcomeWouldDrop, Phase: phase, Applied: false, RuleIDs: ruleIDs, Reason: "drop decision was not applied"}
	case hasAlert:
		return flowmodel.Verdict{Decision: flowmodel.DecisionAlert, Outcome: flowmodel.OutcomeForwarded, Phase: phase, Applied: true, RuleIDs: ruleIDs}
	default:
		return flowmodel.Forwarded(phase)
	}
}
