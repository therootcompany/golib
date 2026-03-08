package main

import "testing"

func TestSlugify(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{
			"https://api.example.com/v2/rooms",
			"api.example.com-v2-rooms.json",
		},
		{
			"https://api.example.com/v2/rooms?limit=10&offset=20",
			"api.example.com-v2-rooms-limit-10-offset-20.json",
		},
		{
			// token param stripped
			"https://api.example.com/data?token=abc123secret&limit=5",
			"api.example.com-data-limit-5.json",
		},
		{
			// api_key stripped
			"https://api.example.com/data?api_key=xyz&format=json",
			"api.example.com-data-format-json.json",
		},
		{
			// long value stripped (>20 chars)
			"https://api.example.com/data?hash=abcdefghijklmnopqrstuvwxyz&page=1",
			"api.example.com-data-page-1.json",
		},
		{
			// access_token stripped
			"https://api.example.com/me?access_token=foo",
			"api.example.com-me.json",
		},
		{
			// auth_code contains "code" — stripped
			"https://example.com/callback?auth_code=xyz&state=ok",
			"example.com-callback-state-ok.json",
		},
		{
			// no query string
			"http://localhost:8080/api/v1/users",
			"localhost-8080-api-v1-users.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := slugify(tt.url)
			if got != tt.want {
				t.Errorf("slugify(%q)\n  got:  %s\n  want: %s", tt.url, got, tt.want)
			}
		})
	}
}
