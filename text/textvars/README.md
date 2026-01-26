# [textvars](https://github.com/therootcompany/golib/tree/main/text/textvars)

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/text/textvars.svg)](https://pkg.go.dev/github.com/therootcompany/golib/text/textvars)

Text replacement functions that handle the empty string / trailing comma problem in a sane way: \
(cuts the character to the left when empty)

Example: Leading space:

```go
textvars.ReplaceVar(`Hey {Name}!`, "Name", "Joe")
// "Hey Joe!"

textvars.ReplaceVar(`Hey {Name}!`, "Name", "")
// "Hey!" 👍

strings.ReplaceAll(`Hey {Name}!`, "{Name}", "")
// "Hey !" 🫤
```

Example: Leading comma:

```go
textvars.ReplaceVar(`Apples,{Fruit},Bananas`, "Fruit", "Oranges")
// "Apples,Oranges,Bananas"

textvars.ReplaceVar(`Apples,{Fruit},Bananas`, "Fruit", "")
// "Apples,Bananas" 👍

strings.ReplaceAll(`Apples,{Fruit},Bananas`, "{Fruit}", "")
// "Apples,,Bananas" 🫤
```

Example: Multiple Vars

```go
tmpl := `{#}. {Name}`
vars := map[string]string{
    "#": "1",
    "Name": "Joe",
}
text, err := textvars.ReplaceVars(tmpl, vars)
// "1. Joe"
// errors if any {...} are left over
```

**Note**: This is the sort of thing that's it's probably better to copy and paste rather than to have as a dependency, but I wanted to have it for myself as a convenience in my own repo of tools, so here it is.

## Other Uses

It seemed like an okay idea at the time, so I also baked in some other uses:

| Syntax     | Example        | "Joe"       | Empty ("") | Comment                       |
| ---------- | -------------- | ----------- | ---------- | ----------------------------- |
| `{Name}`   | `Hey {Name}!`  | `Hey Joe!`  | `Hey!`     | cuts left character if empty  |
| `{Name-}`  | `1,{Name-},3`  | `1,Joe,3`   | `1,3`      | cuts right character if empty |
| `{-Name-}` | `Hey! {Name}!` | `Hey! Joe!` | `Hey!`     | cuts left and right if empty  |
| `{+Name}`  | `Name:{+Name}` | `Name:Joe`  | `Name:`    | keeps left character always   |

However, I haven't actually had the use case for those yet and you probably won't either... so don't use what you don't need. 🙃

I DO NOT plan on making a robust template system. I was only interested in solving the _leading space_ / _trailing comma_ problem for [sendsms](https://github.com/therootcompany/golib/tree/main/cmd/sendsms).

# Legal

CC0-1.0 (Public Domain)
