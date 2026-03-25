package dropper

import (
	"fmt"
	"log"
)

const flagRulePrefix = "flag-auto-"

// EnsureFlagRule creates the automatic flag drop rule for a service if it doesn't already exist.
func EnsureFlagRule(ruleStore *RuleStore, serviceID, flagRegex string) {
	if flagRegex == "" {
		return
	}

	ruleID := flagRulePrefix + serviceID

	// Check if already exists
	if _, exists := ruleStore.GetRule(ruleID); exists {
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
	}

	if err := ruleStore.CreateRule(rule); err != nil {
		log.Printf("Warning: failed to create flag rule for service %s: %v", serviceID, err)
		return
	}
	log.Printf("Flag drop rule created for service %s (pattern: %s)", serviceID, flagRegex)
}

// EnsureFlagRulesForAll creates flag rules for all given service IDs.
func EnsureFlagRulesForAll(ruleStore *RuleStore, serviceIDs []string, flagRegex string) {
	for _, id := range serviceIDs {
		EnsureFlagRule(ruleStore, id, flagRegex)
	}
}
