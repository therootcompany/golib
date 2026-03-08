package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type prompter struct {
	reader *bufio.Reader
	output io.Writer
	tty    *os.File // non-nil if we opened /dev/tty

	// Answer replay/recording
	priorAnswers []string // loaded from .answers file
	priorIdx     int      // next prior answer to use
	answers      []string // all answers this session (for saving)
}

// newPrompter creates a prompter. If the JSON input comes from stdin, we open
// /dev/tty for interactive prompts so they don't conflict.
func newPrompter(inputIsStdin bool) (*prompter, error) {
	p := &prompter{output: os.Stderr}
	if inputIsStdin {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, fmt.Errorf("cannot open /dev/tty for prompts (input is stdin): %w", err)
		}
		p.tty = tty
		p.reader = bufio.NewReader(tty)
	} else {
		p.reader = bufio.NewReader(os.Stdin)
	}
	return p, nil
}

// loadAnswers reads prior answers from a file to use as defaults.
func (p *prompter) loadAnswers(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// Filter out empty trailing lines
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > 0 {
		fmt.Fprintf(p.output, "using prior answers from %s\n", path)
		p.priorAnswers = lines
	}
}

// saveAnswers writes this session's answers to a file.
func (p *prompter) saveAnswers(path string) error {
	if len(p.answers) == 0 {
		return nil
	}
	return os.WriteFile(path, []byte(strings.Join(p.answers, "\n")+"\n"), 0o600)
}

// nextPrior returns the next prior answer if available, or empty string.
func (p *prompter) nextPrior() string {
	if p.priorIdx < len(p.priorAnswers) {
		answer := p.priorAnswers[p.priorIdx]
		p.priorIdx++
		return answer
	}
	return ""
}

// record saves an answer for later writing.
func (p *prompter) record(answer string) {
	p.answers = append(p.answers, answer)
}

func (p *prompter) close() {
	if p.tty != nil {
		p.tty.Close()
	}
}

// ask presents a prompt with a default and valid options. Returns the chosen
// option (lowercase). Options should be lowercase; the default is shown in
// uppercase in the hint.
func (p *prompter) ask(prompt, defaultOpt string, options []string) string {
	// Override default with prior answer if available
	if prior := p.nextPrior(); prior != "" {
		for _, o := range options {
			if prior == o {
				defaultOpt = prior
				break
			}
		}
	}

	hint := make([]string, len(options))
	for i, o := range options {
		if o == defaultOpt {
			hint[i] = strings.ToUpper(o)
		} else {
			hint[i] = o
		}
	}
	for {
		fmt.Fprintf(p.output, "%s [%s] ", prompt, strings.Join(hint, "/"))
		line, err := p.reader.ReadString('\n')
		if err != nil {
			p.record(defaultOpt)
			return defaultOpt
		}
		line = strings.TrimSpace(strings.ToLower(line))
		if line == "" {
			p.record(defaultOpt)
			return defaultOpt
		}
		for _, o := range options {
			if line == o {
				p.record(o)
				return o
			}
		}
		fmt.Fprintf(p.output, "  Please enter one of: %s\n", strings.Join(options, ", "))
	}
}

// askMapOrName presents a combined map/struct+name prompt.
func (p *prompter) askMapOrName(prompt, defaultVal string) string {
	if prior := p.nextPrior(); prior != "" {
		if prior == "m" || prior == "map" {
			defaultVal = prior
		} else if len(prior) > 0 && prior[0] >= 'A' && prior[0] <= 'Z' {
			defaultVal = prior
		}
	}

	hint := defaultVal + "/m"
	if defaultVal == "m" {
		hint = "m"
	}

	for {
		fmt.Fprintf(p.output, "%s [%s] ", prompt, hint)
		line, err := p.reader.ReadString('\n')
		if err != nil {
			p.record(defaultVal)
			return defaultVal
		}
		line = strings.TrimSpace(line)
		if line == "" {
			p.record(defaultVal)
			return defaultVal
		}
		if line == "m" || line == "map" {
			p.record("m")
			return "m"
		}
		if len(line) > 0 && line[0] >= 'A' && line[0] <= 'Z' {
			p.record(line)
			return line
		}
		fmt.Fprintf(p.output, "  Enter a TypeName (starting with uppercase), or 'm' for map\n")
	}
}

// askTypeName presents a prompt for a type name with a suggested default.
func (p *prompter) askTypeName(prompt, defaultVal string) string {
	if prior := p.nextPrior(); prior != "" {
		if len(prior) > 0 && prior[0] >= 'A' && prior[0] <= 'Z' {
			defaultVal = prior
		}
	}

	for {
		fmt.Fprintf(p.output, "%s [%s] ", prompt, defaultVal)
		line, err := p.reader.ReadString('\n')
		if err != nil {
			p.record(defaultVal)
			return defaultVal
		}
		line = strings.TrimSpace(line)
		if line == "" {
			p.record(defaultVal)
			return defaultVal
		}
		if len(line) > 0 && line[0] >= 'A' && line[0] <= 'Z' {
			p.record(line)
			return line
		}
		fmt.Fprintf(p.output, "  Enter a TypeName (starting with uppercase)\n")
	}
}
