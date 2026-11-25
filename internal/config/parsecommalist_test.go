package config

import (
	"reflect"
	"testing"
)

func TestParseCommaList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a,b,c", []string{"a", "b", "c"}},
		{" A , B ,,c ", []string{"a", "b", "c"}}, // trim, lowercase, drop empty
		{"staging,dev-*,*.internal.example.com", []string{"staging", "dev-*", "*.internal.example.com"}},
	}
	for _, c := range cases {
		if got := ParseCommaList(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseCommaList(%q)=%v want %v", c.in, got, c.want)
		}
	}
}
