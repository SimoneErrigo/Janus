package filter

import "sort"

type FieldSchema struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Operators []string `json:"operators"`
}

type Schema struct {
	Fields   []FieldSchema `json:"fields"`
	Patterns []string      `json:"patterns"`
}

func PublicSchema() Schema {
	out := Schema{Patterns: []string{"header.<name>", "query.<name>", "form.<name>", "cookie.<name>", "json.<path>", "decoded.<path>", "dns.<field>", "resp.<field>", "mqtt.<field>"}}
	for _, field := range fields {
		typeName := "string"
		switch field.Type {
		case TypeInt:
			typeName = "int"
		case TypeBool:
			typeName = "bool"
		case TypeBytes:
			typeName = "bytes"
		case TypeHeaders:
			typeName = "headers"
		}
		ops := []string{}
		for _, op := range []Op{OpEq, OpNeq, OpContains, OpIContains, OpMatches, OpStartsWith, OpEndsWith, OpIn, OpGT, OpLT, OpGTE, OpLTE, OpExists, OpMissing} {
			if opCompatible(field.Type, op) {
				ops = append(ops, string(op))
			}
		}
		out.Fields = append(out.Fields, FieldSchema{Name: field.Name, Type: typeName, Operators: ops})
	}
	sort.Slice(out.Fields, func(i, j int) bool { return out.Fields[i].Name < out.Fields[j].Name })
	return out
}
