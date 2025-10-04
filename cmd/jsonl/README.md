# JSONL

An example of using `encoding/json`'s `dec.More()` to read JSONL natively. \
(because it can read any valid sequence of back-to-back JSON objects)

```go
package main

import (
   "encoding/json"
   "fmt"
   "os"
)

func main() {
   decoder := json.NewDecoder(os.Stdin)

   var err error
   for decoder.More() {
      var data any
      if err = decoder.Decode(&data); err != nil {
         break
      }
      fmt.Printf("Decoded: %#v\n\n", data)
   }
   if err != nil {
      fmt.Fprintf(os.Stderr, "error decoding JSON: %v\n", err)
   }

   fmt.Printf("Done\n")
}
```

## Strict JSONL

This will parse strict JSONL.

`./messages.jsonl`:

```json5
{"name":"Alice","age":25}
{"name":"Bob","age":30}
{"name":"Charlie","age":35}
```

```text
Decoded: map[string]interface {}{"age":25, "name":"Alice"}

Decoded: map[string]interface {}{"age":30, "name":"Bob"}

Decoded: map[string]interface {}{"age":35, "name":"Charlie"}
```

## Back-to-back JSON

It will also parse... anything else.

`./messages.jsonish`:

```json5
null

true
false

0
1

"hello"

[2, 11, 37, 42]

{"name":"Alice","age":25}
{
   "name":"Bob",
   "age":30
}


{
   "name":
      "Charlie",
         "age":
            35
               }
```

```text
Decoded: <nil>

Decoded: true

Decoded: false

Decoded: 0

Decoded: 1

Decoded: "hello"

Decoded: []interface {}{2, 11, 37, 42}

Decoded: map[string]interface {}{"age":25, "name":"Alice"}

Decoded: map[string]interface {}{"age":30, "name":"Bob"}

Decoded: map[string]interface {}{"age":35, "name":"Charlie"}
```

## Non-JSON

`dec.More()` does not stop after error. You must check the return errors and break out yourself.

```json5
{"name":"Alice","age":25}
{"name":"Bob","age":30}
{"name":"Charlie"
```

```text
Decoded: map[string]interface {}{"age":25, "name":"Alice"}

Decoded: map[string]interface {}{"age":30, "name":"Bob"}

error decoding JSON: unexpected EOF

Done
```
