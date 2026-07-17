package rounddiff

import "testing"

func TestSuspicionTagsDoesNotTreatPlainCommentAsSQL(t *testing.T) {
	if tags := SuspicionTags(`plain /* documentation */ text`); len(tags) != 0 {
		t.Fatalf("plain comment produced suspicion tags: %v", tags)
	}
}

func TestSuspicionTagsKeepsSQLCommentObfuscation(t *testing.T) {
	for _, input := range []string{`UNION/**/SELECT password FROM users`, `1/**/OR/**/1=1`, `/*!50000 SELECT * FROM users */`} {
		t.Run(input, func(t *testing.T) {
			tags := SuspicionTags(input)
			found := false
			for _, tag := range tags {
				if tag == TagSQLi || tag == TagSQLiSyntax {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("SQL comment obfuscation was not tagged: %v", tags)
			}
		})
	}
}
