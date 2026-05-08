package dropper

import (
	"fmt"
	"log"
)

// EnsureFlagRule creates or corrects the automatic flag alert rule for a service.
// The flag regex must always be action=alert: dropping flag-bearing packets breaks the checker.
//
// The rule's Expression covers body, url and header — flags can appear in any
// of these.
func EnsureFlagRule(ruleStore *RuleStore, serviceID, flagRegex string) {
	if flagRegex == "" {
		return
	}

	ruleID := flagRulePrefix + serviceID
	wantedExpr := flagRuleExpression(flagRegex)

	if existing, exists := ruleStore.GetRule(ruleID); exists {
		needsUpdate := false
		if existing.Action != ActionAlert {
			existing.Action = ActionAlert
			needsUpdate = true
		}
		if existing.Expression != wantedExpr {
			existing.Expression = wantedExpr
			needsUpdate = true
		}
		if needsUpdate {
			if err := ruleStore.UpdateRule(existing); err != nil {
				log.Printf("Warning: failed to correct flag rule for service %s: %v", serviceID, err)
			} else {
				log.Printf("Flag rule corrected for service %s", serviceID)
			}
		}
		return
	}

	rule := &Rule{
		ID:         ruleID,
		ServiceID:  serviceID,
		Name:       fmt.Sprintf("Auto flag filter (%s)", serviceID),
		Expression: wantedExpr,
		Priority:   0, // highest priority
		Enabled:    true,
		Action:     ActionAlert,
	}

	if err := ruleStore.CreateRule(rule); err != nil {
		log.Printf("Warning: failed to create flag rule for service %s: %v", serviceID, err)
		return
	}
	log.Printf("Flag alert rule created for service %s (pattern: %s)", serviceID, flagRegex)
}

func flagRuleExpression(flagRegex string) string {
	q := quoteString(flagRegex)
	return "body matches " + q + " OR url matches " + q + " OR header matches " + q
}

// EnsureFlagRulesForAll creates/corrects flag rules for all given service IDs.
func EnsureFlagRulesForAll(ruleStore *RuleStore, serviceIDs []string, flagRegex string) {
	for _, id := range serviceIDs {
		EnsureFlagRule(ruleStore, id, flagRegex)
	}
}
