// smsgwhooks-to-tsv - Converts messages.jsonl webhook events to TSV/CSV
//
// Authored in 2026 by AJ ONeal <aj@therootcompany.com>, assisted by Grok Ai.
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/jszwec/csvutil"
)

type SmsReceivedPayload struct {
	Message     string `json:"message"     csv:"message"`
	MessageID   string `json:"messageId"   csv:"messageId"`
	PhoneNumber string `json:"phoneNumber" csv:"phoneNumber"`
	ReceivedAt  string `json:"receivedAt"  csv:"receivedAt"`
	SimNumber   int    `json:"simNumber"   csv:"simNumber"`
}

type WebhookEvent struct {
	DeviceID   string             `json:"deviceId"    csv:"deviceId"`
	Event      string             `json:"event"       csv:"event"`
	ID         string             `json:"id"          csv:"id"`
	Payload    SmsReceivedPayload `json:"payload"     csv:",inline"`
	WebhookID  string             `json:"webhookId"   csv:"webhookId"`
	XSignature string             `json:"x-signature" csv:"x-signature"`
	XTimestamp int64              `json:"x-timestamp" csv:"x-timestamp"`
}

type MainConfig struct {
	out   string
	comma string
	in    string
}

func main() {
	cfg := MainConfig{}

	fs := flag.NewFlagSet("smsgwhooks-to-tsv", flag.ExitOnError)

	fs.StringVar(&cfg.out, "o", "-", "output file ('-' = stdout)")
	fs.StringVar(&cfg.comma, "comma", "\t", "field separator (default: tab)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: jsonl-to-tsv [flags] [input.jsonl]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Converts JSONL webhook events to TSV (or CSV with custom separator).\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  jsonl-to-tsv messages.jsonl\n")
		fmt.Fprintf(os.Stderr, "  cat messages.jsonl | jsonl-to-tsv -\n")
		fmt.Fprintf(os.Stderr, "  jsonl-to-tsv -o ./out.tsv messages.jsonl\n")
		fmt.Fprintf(os.Stderr, "  jsonl-to-tsv --comma , -o ./out.csv messages.jsonl\n")
		fmt.Fprintf(os.Stderr, "  jsonl-to-tsv -o - messages.jsonl           # explicit stdout\n")
	}

	_ = fs.Parse(os.Args[1:])

	fi, _ := os.Stdin.Stat()
	isProbablyPipe := (fi.Mode() & os.ModeCharDevice) == 0
	if fs.NArg() == 0 && !isProbablyPipe {
		fs.Usage()
		os.Exit(1)
	}

	var in io.Reader = os.Stdin
	if cfg.in = fs.Arg(0); cfg.in != "" && cfg.in != "-" {
		f, err := os.Open(cfg.in)
		if err != nil {
			log.Fatalf("open input: %v", err)
		}
		defer func() { _ = f.Close() }()
		in = f
	}

	var out io.Writer = os.Stdout
	if cfg.out != "-" {
		f, err := os.Create(cfg.out)
		if err != nil {
			log.Fatalf("create output: %v", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	csvWriter := csv.NewWriter(out)
	csvWriter.Comma = rune((cfg.comma)[0])
	csvWriter.UseCRLF = false

	enc := csvutil.NewEncoder(csvWriter)

	// write header
	_ = enc.EncodeHeader(WebhookEvent{})

	dec := json.NewDecoder(in)
	for dec.More() {
		var evt WebhookEvent
		if err := dec.Decode(&evt); err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("decode error, skipping: %v", err)
			continue
		}
		if evt.Event != "sms:received" {
			continue
		}

		if err := enc.Encode(evt); err != nil {
			log.Fatalf("encode error: %v", err)
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		log.Printf("flush error: %v", err)
	}
}
