package csvx

import (
	"reflect"
	"testing"
)

func TestListishUnmarshalCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Listish
	}{
		{name: "comma", in: "admin,hr,pm", want: Listish{"admin", "hr", "pm"}},
		{name: "whitespace", in: "admin hr\tpm", want: Listish{"admin", "hr", "pm"}},
		{name: "mixed", in: " admin, hr\npm ", want: Listish{"admin", "hr", "pm"}},
		{name: "empty", in: " , \t", want: Listish{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Listish
			if err := got.UnmarshalCSV([]byte(tt.in)); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}
