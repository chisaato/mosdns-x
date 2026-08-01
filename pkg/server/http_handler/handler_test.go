package http_handler

import (
	"net/url"
	"reflect"
	"testing"
)

func Test_parseClientIDs(t *testing.T) {
	tests := []struct {
		name   string
		u      *url.URL
		prefix string
		want   []string
	}{
		{
			name:   "exact path, no ids",
			u:      &url.URL{Path: "/dns-query"},
			prefix: "/dns-query",
			want:   nil,
		},
		{
			name:   "single id",
			u:      &url.URL{Path: "/dns-query/family"},
			prefix: "/dns-query",
			want:   []string{"family"},
		},
		{
			name:   "multiple ids",
			u:      &url.URL{Path: "/dns-query/edu/cn"},
			prefix: "/dns-query",
			want:   []string{"edu", "cn"},
		},
		{
			name:   "empty segments are dropped",
			u:      &url.URL{Path: "/dns-query/a//b/"},
			prefix: "/dns-query",
			want:   []string{"a", "b"},
		},
		{
			name: "encoded slash is one id via RawPath",
			u: &url.URL{
				Path:    "/dns-query/a/b",
				RawPath: "/dns-query/a%2Fb",
			},
			prefix: "/dns-query",
			want:   []string{"a/b"},
		},
		{
			name: "percent encoded id is decoded",
			u: &url.URL{
				Path:    "/dns-query/a b",
				RawPath: "/dns-query/a%20b",
			},
			prefix: "/dns-query",
			want:   []string{"a b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseClientIDs(tt.u, tt.prefix)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseClientIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}
