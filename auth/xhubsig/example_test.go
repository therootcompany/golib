package xhubsig_test

import (
	"fmt"
	"net/http"

	"github.com/therootcompany/golib/auth/xhubsig"
)

func ExampleSign() {
	sig := xhubsig.Sign(xhubsig.SHA256, "It's a Secret to Everybody", []byte("Hello, World!"))
	fmt.Println(sig)
	// Output:
	// sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
}

func ExampleVerify() {
	body := []byte("Hello, World!")
	sig := xhubsig.Sign(xhubsig.SHA256, "secret", body)

	err := xhubsig.Verify(xhubsig.SHA256, "secret", body, sig)
	fmt.Println(err)
	// Output:
	// <nil>
}

func ExampleXHubSig_Require() {
	x := xhubsig.New("webhookSecret")

	mux := http.NewServeMux()
	mux.Handle("POST /webhook", x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// body is verified and re-readable here
		w.WriteHeader(http.StatusNoContent)
	})))
}
