package main

import (
	"reflect"
	"testing"
)

func TestSplitAndTrimCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "   ", want: nil},
		{name: "single", in: "https://accounts.google.com", want: []string{"https://accounts.google.com"}},
		{name: "multi", in: "a,b,c", want: []string{"a", "b", "c"}},
		{name: "trim each", in: " a , b , c ", want: []string{"a", "b", "c"}},
		{name: "leading comma", in: ",https://oidc.example", want: []string{"https://oidc.example"}},
		{name: "trailing comma", in: "https://oidc.example,", want: []string{"https://oidc.example"}},
		{name: "double comma", in: "a,,b", want: []string{"a", "b"}},
		{name: "all empty entries", in: " , ,  ,", want: nil},
		{name: "real-world issuers", in: "https://accounts.google.com, https://token.actions.githubusercontent.com", want: []string{"https://accounts.google.com", "https://token.actions.githubusercontent.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitAndTrimCSV(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitAndTrimCSV(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
