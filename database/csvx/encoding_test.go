package csvx

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"testing"
)

type byteRoundTrip struct {
	Value []byte `json:"value"`
}

func TestSerializeJSONNilSliceAsEmptyArray(t *testing.T) {
	var data bytes.Buffer
	if err := SerializeJSON[struct{}](json.NewEncoder(&data), nil); err != nil {
		t.Fatal(err)
	}
	if got, want := data.String(), "[]\n"; got != want {
		t.Fatalf("JSON = %q, want %q", got, want)
	}
}

func TestByteRoundTripPrefersHex(t *testing.T) {
	want := []byte{0x79, 0xf7, 0x5e, 0xdd, 0xce, 0xfe, 0x5d, 0xe5}
	var data bytes.Buffer
	writer := csv.NewWriter(&data)
	writer.Comma = '\t'
	if err := SerializeCSV(writer, []byteRoundTrip{{Value: want}}); err != nil {
		t.Fatal(err)
	}

	reader := csv.NewReader(&data)
	reader.Comma = '\t'
	got, err := ParseCSV[byteRoundTrip](reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Value) != string(want) {
		t.Fatalf("value = %x, want %x", got[0].Value, want)
	}
}
