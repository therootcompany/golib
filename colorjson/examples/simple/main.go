package main

import (
	"encoding/json"
	"fmt"

	"github.com/therootcompany/golib/colorjson"
)

func main() {
	str := `{
      "str": "foo",
      "num": 100,
      "bool": false,
      "null": null,
      "array": ["foo", "bar", "baz"],
      "obj": { "a": 1, "b": 2 }
    }`

	var obj map[string]interface{}
	json.Unmarshal([]byte(str), &obj)

	// Marshall the Colorized JSON
	s, _ := colorjson.Marshal(obj)
	fmt.Println(string(s))
}
