package dropper

import (
	"fmt"
	"log"
)

// EnsureFlagRule creates or corrects the automatic flag alert rule for a service.
// The flag regex must always be action=alert: dropping flag-bearing packets breaks the checker.
func EnsureFlagRule(ruleStore *RuleStore, serviceID, flagRegex string) {
	if flagRegex == "" {
		return
	}

	ruleID := flagRulePrefix + serviceID

	// Check if already exists
	if existing, exists := ruleStore.GetRule(ruleID); exists {
		// Correct action to alert if it was set to drop or both
		if existing.Action != ActionAlert {
			existing.Action = ActionAlert
			if err := ruleStore.UpdateRule(existing); err != nil {
				log.Printf("Warning: failed to correct flag rule action for service %s: %v", serviceID, err)
			} else {
				log.Printf("Flag rule corrected to alert-only for service %s", serviceID)
			}
		}
		return
	}

	rule := &Rule{
		ID:        ruleID,
		ServiceID: serviceID,
		Name:      fmt.Sprintf("Auto flag filter (%s)", serviceID),
		Type:      MatchRegex,
		Scope:     ScopeBody,
		Pattern:   flagRegex,
		Priority:  0, // highest priority
		Enabled:   true,
		Action:    ActionAlert,
	}

	if err := ruleStore.CreateRule(rule); err != nil {
		log.Printf("Warning: failed to create flag rule for service %s: %v", serviceID, err)
		return
	}
	log.Printf("Flag alert rule created for service %s (pattern: %s)", serviceID, flagRegex)
}

// EnsureFlagRulesForAll creates/corrects flag rules for all given service IDs.
func EnsureFlagRulesForAll(ruleStore *RuleStore, serviceIDs []string, flagRegex string) {
	for _, id := range serviceIDs {
		EnsureFlagRule(ruleStore, id, flagRegex)
	}
}
