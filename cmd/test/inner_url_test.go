package test

import "testing"

func TestInnerGitopsURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "outer https with multi-label domain",
			in:   "https://test-workspace-1234-gitops.bs-test-workspace-1234.localhost",
			want: "https://test-workspace-1234-gitops--inner.bs-test-workspace-1234.localhost",
		},
		{
			name: "outer http",
			in:   "http://foo-gitops.example.com",
			want: "http://foo-gitops--inner.example.com",
		},
		{
			name: "outer with port",
			in:   "https://foo-gitops.example.com:8443",
			want: "https://foo-gitops--inner.example.com:8443",
		},
		{
			name: "already inner — no-op",
			in:   "https://foo-gitops--inner.example.com",
			want: "https://foo-gitops--inner.example.com",
		},
		{
			name: "single-label host",
			in:   "http://gitops",
			want: "http://gitops--inner",
		},
		{
			name: "malformed URL falls back to original",
			in:   "::not-a-url",
			want: "::not-a-url",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := innerGitopsURL(tc.in)
			if got != tc.want {
				t.Errorf("innerGitopsURL(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}
