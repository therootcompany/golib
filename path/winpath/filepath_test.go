package winpath_test

import (
	"testing"

	winpath "github.com/therootcompany/golib/path/winpath"
)

type stringTest struct {
	input  string
	output string
}

func TestBase(t *testing.T) {
	for _, tc := range []stringTest{
		{input: `C:\foo\bar\baz.txt`, output: "baz.txt"},
		{input: `foo\bar\baz.txt`, output: "baz.txt"},
		{input: `baz.txt`, output: "baz.txt"},
		{input: `\\.\pipe\baz.txt`, output: "baz.txt"},
		{input: ".", output: "."},
		{input: "..", output: ".."},
		{input: "/", output: "\\"},
		{input: "", output: "."},
	} {
		result := winpath.Base(tc.input)
		if result != tc.output {
			t.Errorf("winpath.Base(%q) = %q; want %q", tc.input, result, tc.output)
		}
	}
}

func TestDir(t *testing.T) {
	for _, tc := range []stringTest{
		{input: `C:\foo\bar\baz.txt`, output: `C:\foo\bar`},
		{input: `foo\bar\baz.txt`, output: `foo\bar`},
		{input: `baz.txt`, output: `.`},
		{input: ".", output: "."},
		{input: "..", output: "."},
		{input: "C:\\", output: "C:\\"},
		{input: "", output: "."},
	} {
		result := winpath.Dir(tc.input)
		if result != tc.output {
			t.Errorf("winpath.Dir(%q) = %q; want %q", tc.input, result, tc.output)
		}
	}
}

func TestJoin(t *testing.T) {
	for _, tc := range []struct {
		parts  []string
		output string
	}{
		{parts: []string{`C:\foo`, "bar", "baz.txt"}, output: `C:\foo\bar\baz.txt`},
		{parts: []string{`foo`, "bar", "baz.txt"}, output: `foo\bar\baz.txt`},
		{parts: []string{`baz.txt`}, output: `baz.txt`},
		{parts: []string{`C:\`, "foo", "..", "baz.txt"}, output: `C:\baz.txt`},
		{parts: []string{`C:\`, "..", "baz.txt"}, output: `C:\baz.txt`},
		{parts: []string{"..", "baz.txt"}, output: `..\baz.txt`},
	} {
		result := winpath.Join(tc.parts...)
		if result != tc.output {
			t.Errorf("winpath.Join(%q) = %q; want %q", tc.parts, result, tc.output)
		}
	}
}

func TestExt(t *testing.T) {
	for _, tc := range []stringTest{
		{input: `C:\foo\bar\baz.txt`, output: ".txt"},
		{input: `foo\bar\baz.tar.gz`, output: ".gz"},
		{input: `baz`, output: ""},
		{input: `\baz.`, output: "."},
	} {
		result := winpath.Ext(tc.input)
		if result != tc.output {
			t.Errorf("winpath.Ext(%q) = %q; want %q", tc.input, result, tc.output)
		}
	}
}

func TestSplit(t *testing.T) {
	for _, tc := range []struct {
		input string
		dir   string
		base  string
	}{
		{input: `C:\foo\bar\baz.txt`, dir: `C:\foo\bar\`, base: "baz.txt"},
		{input: `foo\bar\baz.txt`, dir: `foo\bar\`, base: "baz.txt"},
		{input: `baz.txt`, dir: ``, base: "baz.txt"},
		{input: `\\.\pipe\baz.txt`, dir: `\\.\pipe\`, base: "baz.txt"},
		{input: `\\network\path\baz.txt`, dir: `\\network\path\`, base: "baz.txt"},
	} {
		dir, base := winpath.Split(tc.input)
		if dir != tc.dir || base != tc.base {
			t.Errorf("winpath.Split(%q) = (%q, %q); want (%q, %q)", tc.input, dir, base, tc.dir, tc.base)
		}
	}
}

func TestClean(t *testing.T) {
	for _, tc := range []stringTest{
		{input: `C:\foo\..\bar\baz.txt`, output: `C:\bar\baz.txt`},
		{input: `foo\..\bar\baz.txt`, output: `bar\baz.txt`},
		{input: `.\baz.txt`, output: `baz.txt`},
		{input: `C:\foo\.\bar\baz.txt`, output: `C:\foo\bar\baz.txt`},
		{input: `C:\foo\\bar\\baz.txt`, output: `C:\foo\bar\baz.txt`},
		{input: `C:\foo\bar\..\..\baz.txt`, output: `C:\baz.txt`},
		{input: `..\baz.txt`, output: `..\baz.txt`},
		{input: `\\network\path\..\baz.txt`, output: `\\network\path\baz.txt`},
	} {
		result := winpath.Clean(tc.input)
		if result != tc.output {
			t.Errorf("winpath.Clean(%q) = %q; want %q", tc.input, result, tc.output)
		}
	}
}

func TestIsAbs(t *testing.T) {
	for _, tc := range []struct {
		input string
		isAbs bool
	}{
		{input: `C:\foo\bar\baz.txt`, isAbs: true},
		{input: `\foo\bar\baz.txt`, isAbs: false},
		{input: `\\network\path`, isAbs: true},
		{input: `foo\bar\baz.txt`, isAbs: false},
		{input: `.\baz.txt`, isAbs: false},
		{input: `..\baz.txt`, isAbs: false},
	} {
		result := winpath.IsAbs(tc.input)
		if result != tc.isAbs {
			t.Errorf("winpath.IsAbs(%q) = %v; want %v", tc.input, result, tc.isAbs)
		}
	}
}

func TestVolumeName(t *testing.T) {
	for _, tc := range []stringTest{
		{input: `C:\foo\bar\b.txt`, output: "C:"},
		{input: `\\network\path\b.txt`, output: `\\network\path`},
		{input: `\\.\C:\b.txt`, output: `\\.\C:`},
		{input: `foo\bar\b.txt`, output: ""},
		{input: `\foo\bar\b.txt`, output: ""},
	} {
		result := winpath.VolumeName(tc.input)
		if result != tc.output {
			t.Errorf("winpath.VolumeName(%q) = %q; want %q", tc.input, result, tc.output)
		}
	}
}

func TestToSlash(t *testing.T) {
	for _, tc := range []stringTest{
		{input: `C:\foo\bar\b.txt`, output: "C:/foo/bar/b.txt"},
		{input: `foo\bar\b.txt`, output: "foo/bar/b.txt"},
		{input: `C:/foo/bar/b.txt`, output: "C:/foo/bar/b.txt"},
	} {
		result := winpath.ToSlash(tc.input)
		if result != tc.output {
			t.Errorf("winpath.ToSlash(%q) = %q; want %q", tc.input, result, tc.output)
		}
	}
}

func TestFromSlash(t *testing.T) {
	for _, tc := range []stringTest{
		{input: `C:/foo/bar/b.txt`, output: `C:\foo\bar\b.txt`},
		{input: `foo/bar/b.txt`, output: `foo\bar\b.txt`},
		{input: `C:\foo\bar\b.txt`, output: `C:\foo\bar\b.txt`},
	} {
		result := winpath.FromSlash(tc.input)
		if result != tc.output {
			t.Errorf("winpath.FromSlash(%q) = %q; want %q", tc.input, result, tc.output)
		}
	}
}
