package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

//go:embed index.html
var indexHTML []byte

type Message struct {
	Time string `json:"time"`
	Nick string `json:"nick"`
	Text string `json:"text"`
}

var sse = NewSSEChannel()

func main() {
	mux := http.NewServeMux()
	// Serve static HTML
	//mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(indexHTML)
	})

	// SSE endpoint
	mux.HandleFunc("GET /api/events", handleSSE)

	// POST endpoint to send messages
	mux.HandleFunc("POST /api/send", handleSend)

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // helps nginx / some proxies

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sse.Subscribe(AddrStr(r.RemoteAddr))
	defer sse.Unsubscribe(AddrStr(r.RemoteAddr))

	fmt.Fprintf(w, "event: system\ndata: {\"time\":\"%s\",\"text\":\"You joined the room\"}\n\n", time.Now().Format("15:04"))
	flusher.Flush()

	// Forward messages to this client
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-sse.Member(AddrStr(r.RemoteAddr)).C:
			if !ok {
				return
			}

			// SSE format:
			// : comment
			// event: optional_name
			// data: data
			// data: more data
			//
			// : extra newline to end data
			if msg.Event != "" {
				fmt.Fprintf(w, "event: %s\n", msg.Event)
			}
			fmt.Fprintf(w, "%s: %s\n\n", msg.Type, msg.Data)
			flusher.Flush()
		}
	}
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad form", http.StatusBadRequest)
		return
	}

	nick := r.FormValue("nick")
	text := r.FormValue("text")
	if text == "" {
		http.Error(w, "Message required", http.StatusBadRequest)
		return
	}

	if nick == "" {
		nick = "Anonymous"
	}

	// In the broadcast loop (handleSend)
	msg := Message{
		Time: time.Now().Format("15:04"),
		Nick: nick,
		Text: text,
	}
	payload, _ := json.Marshal(msg)

	sse.Broadcast(payload)

	w.WriteHeader(http.StatusAccepted)
}
