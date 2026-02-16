package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/therootcompany/golib/cmd/api-example/db"

	"github.com/jackc/pgx/v5/pgxpool"
)

type API struct {
	BootTime  time.Time
	StartTime time.Time
	PG        *pgxpool.Pool
	Queries   *db.Queries
}

type APIStatus struct {
	SystemSeconds float64 `json:"system_seconds"`
	SystemUptime  string  `json:"system_uptime"`
	APISeconds    float64 `json:"api_seconds"`
	APIUptime     string  `json:"api_uptime"`
}

type Greeting struct {
	Message string `json:"message,omitempty"`
}

func (a *API) HandleStatus(w http.ResponseWriter, r *http.Request) {
	systemUptime := time.Since(a.BootTime)
	apiUptime := time.Since(a.StartTime)
	apiStatus := APIStatus{
		SystemSeconds: systemUptime.Seconds(),
		SystemUptime:  FormatDuration(systemUptime),
		APISeconds:    apiUptime.Seconds(),
		APIUptime:     FormatDuration(apiUptime),
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(apiStatus)
}

func (a *API) HandleGreet(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if subject == "" {
		subject = "World"
	}

	msg := Greeting{
		Message: fmt.Sprintf("Hello, %s!", subject),
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(msg)
}
