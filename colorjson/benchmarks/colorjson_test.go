package colorjson_test

import (
	"testing"

	"github.com/hokaccha/go-prettyjson"
	"github.com/therootcompany/golib/colorjson"
)

func BenchmarkMarshall(b *testing.B) {
	simpleMap := make(map[string]any)
	simpleMap["a"] = 1
	simpleMap["b"] = "bee"
	simpleMap["c"] = [3]float64{1, 2, 3}
	simpleMap["d"] = [3]string{"one", "two", "three"}

	for b.Loop() {
		_, _ = colorjson.Marshal(simpleMap)
	}
}

func BenchmarkPrettyJSON(b *testing.B) {
	simpleMap := make(map[string]any)
	simpleMap["a"] = 1
	simpleMap["b"] = "bee"
	simpleMap["c"] = [3]float64{1, 2, 3}
	simpleMap["d"] = [3]string{"one", "two", "three"}

	for b.Loop() {
		_, _ = prettyjson.Marshal(simpleMap)
	}
}
