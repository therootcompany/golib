package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/therootcompany/golib/io/transform/gsheet2csv"
)

func TestConvert(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		noHeader  bool
		noExport  bool
		want      string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "basic 3-column with header",
			noHeader: false,
			input: "KEY,VALUE,COMMENT\n" +
				"FOO,bar,comment here\n" +
				"BAZ,qux,another comment\n",
			want: "# comment here\nexport FOO='bar'\n# another comment\nexport BAZ='qux'\n",
		},
		{
			name:     "3-column with --no-header",
			noHeader: true,
			input: "KEY,VALUE,COMMENT\n" +
				"FOO,bar,comment here\n",
			want: "# COMMENT\nexport KEY='VALUE'\n# comment here\nexport FOO='bar'\n",
		},
		{
			name:     "extra columns ignored",
			noHeader: false,
			input: "KEY,VALUE,COMMENT,URL,NOTES\n" +
				"FOO,bar,comment,https://example.com,extra notes\n",
			want: "# comment\nexport FOO='bar'\n",
		},
		{
			name:     "2-column no comment",
			noHeader: false,
			input: "KEY,VALUE\n" +
				"FOO,bar\n" +
				"BAZ,qux\n",
			want: "export FOO='bar'\nexport BAZ='qux'\n",
		},
		{
			name:     "empty comment column",
			noHeader: false,
			input: "KEY,VALUE,COMMENT\n" +
				"FOO,bar,\n" +
				"BAZ,qux,has comment\n",
			want: "export FOO='bar'\n# has comment\nexport BAZ='qux'\n",
		},
		{
			name:     "comment preserved",
			noHeader: false,
			input: "# This is a comment\n" +
				"KEY,VALUE,COMMENT\n" +
				"FOO,bar,note\n",
			want: "# This is a comment\n# note\nexport FOO='bar'\n",
		},
		{
			name:     "multi-line comment",
			noHeader: false,
			input: "KEY,VALUE,COMMENT\n" +
				"FOO,bar,\"line1\nline2\"\n",
			want: "# line1\n# line2\nexport FOO='bar'\n",
		},
		{
			name:     "multi-line value",
			noHeader: false,
			input: "KEY,VALUE,COMMENT\n" +
				"FOO,\"val1\nval2\",note\n",
			want: "# note\nexport FOO='val1\nval2'\n",
		},
		{
			name:     "single quotes in value escaped",
			noHeader: false,
			input: "KEY,VALUE,COMMENT\n" +
				"FOO,it's value,note\n",
			want: "# note\nexport FOO='it'\"'\"'s value'\n",
		},
		{
			name:      "invalid key errors",
			noHeader:  false,
			input:     "KEY,VALUE,COMMENT\ninvalid-key,val,note\n",
			wantErr:   true,
			errSubstr: "invalid key",
		},
		{
			name:     "export prefix optional",
			noHeader: false,
			noExport: true,
			input: "KEY,VALUE,COMMENT\n" +
				"FOO,bar,note\n",
			want: "# note\nFOO='bar'\n",
		},
		{
			name:     "empty key produces blank line",
			noHeader: false,
			input: "KEY,VALUE,COMMENT\n" +
				",value,note\n" +
				"FOO,bar,note\n",
			want: "\n# note\nexport FOO='bar'\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gsr := gsheet2csv.NewReader(strings.NewReader(tt.input))
			gsr.Comment = 0
			gsr.FieldsPerRecord = -1

			var out bytes.Buffer
			err := convert(gsr, &out, tt.noHeader, tt.noExport)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			got := out.String()
			if got != tt.want {
				t.Errorf("output mismatch:\ngot:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestIsValidKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"FOO", true},
		{"FOO_BAR", true},
		{"FOO123", true},
		{"A1B2C3", true},
		{"", true},
		{"foo", false},
		{"FOO-BAR", false},
		{"FOO.BAR", false},
		{"FOO BAR", false},
		{"${FOO}", false},
		{"123ABC", true},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := isValidKey(tt.key)
			if got != tt.want {
				t.Errorf("isValidKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestSanitizeComment(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple comment",
			input: "note",
			want:  "# note\n",
		},
		{
			name:  "comment with leading/trailing space",
			input: "  note  ",
			want:  "# note\n",
		},
		{
			name:  "multi-line comment",
			input: "line1\nline2",
			want:  "# line1\n# line2\n",
		},
		{
			name:  "multi-line with CRLF",
			input: "line1\r\nline2",
			want:  "# line1\n# line2\n",
		},
		{
			name:  "empty comment",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeComment(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeComment(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
