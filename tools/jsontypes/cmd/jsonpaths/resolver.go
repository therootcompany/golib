package main

import (
	"fmt"
	"strings"

	"github.com/therootcompany/golib/tools/jsontypes"
)

// newCLIResolver returns a jsontypes.Resolver that uses a prompter for terminal I/O.
func newCLIResolver(p *prompter) jsontypes.Resolver {
	return func(d *jsontypes.Decision) error {
		switch d.Kind {
		case jsontypes.DecideMapOrStruct:
			return cliMapOrStruct(p, d)
		case jsontypes.DecideTypeName:
			return cliTypeName(p, d)
		case jsontypes.DecideTupleOrList:
			return cliTupleOrList(p, d)
		case jsontypes.DecideUnifyShapes:
			return cliUnifyShapes(p, d)
		case jsontypes.DecideShapeName:
			return cliShapeName(p, d)
		case jsontypes.DecideNameCollision:
			return cliNameCollision(p, d)
		default:
			d.Response = d.Default
			return nil
		}
	}
}

func cliMapOrStruct(p *prompter, d *jsontypes.Decision) error {
	fmt.Fprintf(p.output, "\nAt %s\n", d.Path)
	fmt.Fprintf(p.output, "  Object with %d keys:\n", len(d.Fields))
	for _, f := range d.Fields {
		fmt.Fprintf(p.output, "    %s: %s\n", f.Name, f.Preview)
	}

	defaultVal := d.Default.Name
	if d.Default.IsMap {
		defaultVal = "m"
	}

	answer := p.askMapOrName("Struct name (or 'm' for map)?", defaultVal)
	if answer == "m" {
		d.Response = jsontypes.Response{IsMap: true}
	} else {
		d.Response = jsontypes.Response{Name: answer}
	}
	return nil
}

func cliTypeName(p *prompter, d *jsontypes.Decision) error {
	fmt.Fprintf(p.output, "\nAt %s\n", d.Path)
	fmt.Fprintf(p.output, "  Struct with %d fields:\n", len(d.Fields))
	for _, f := range d.Fields {
		fmt.Fprintf(p.output, "    %s: %s\n", f.Name, f.Preview)
	}

	name := p.askTypeName("Name for this type?", d.Default.Name)
	d.Response = jsontypes.Response{Name: name}
	return nil
}

func cliTupleOrList(p *prompter, d *jsontypes.Decision) error {
	fmt.Fprintf(p.output, "\nAt %s\n", d.Path)
	fmt.Fprintf(p.output, "  Short array with %d elements of mixed types:\n", len(d.Elements))
	for _, e := range d.Elements {
		fmt.Fprintf(p.output, "    [%d]: %s\n", e.Index, e.Preview)
	}

	choice := p.ask("Is this a [l]ist or a [t]uple?", "l", []string{"l", "t"})
	d.Response = jsontypes.Response{IsTuple: choice == "t"}
	return nil
}

func cliUnifyShapes(p *prompter, d *jsontypes.Decision) error {
	const maxFields = 8

	totalInstances := 0
	for _, s := range d.Shapes {
		totalInstances += s.Instances
	}

	fmt.Fprintf(p.output, "\nAt %s — %d shapes (%d instances):\n",
		d.Path, len(d.Shapes), totalInstances)

	if len(d.SharedFields) > 0 {
		preview := d.SharedFields
		if len(preview) > maxFields {
			preview = preview[:maxFields]
		}
		fmt.Fprintf(p.output, "  shared fields (%d): %s", len(d.SharedFields), strings.Join(preview, ", "))
		if len(d.SharedFields) > maxFields {
			fmt.Fprintf(p.output, ", ...")
		}
		fmt.Fprintln(p.output)
	} else {
		fmt.Fprintf(p.output, "  no shared fields\n")
	}

	shownShapes := d.Shapes
	if len(shownShapes) > 5 {
		shownShapes = shownShapes[:5]
	}
	for _, s := range shownShapes {
		if len(s.UniqueFields) == 0 {
			fmt.Fprintf(p.output, "  shape %d (%d instances): no unique fields\n", s.Index+1, s.Instances)
			continue
		}
		preview := s.UniqueFields
		if len(preview) > maxFields {
			preview = preview[:maxFields]
		}
		fmt.Fprintf(p.output, "  shape %d (%d instances): +%d unique: %s",
			s.Index+1, s.Instances, len(s.UniqueFields), strings.Join(preview, ", "))
		if len(s.UniqueFields) > maxFields {
			fmt.Fprintf(p.output, ", ...")
		}
		fmt.Fprintln(p.output)
	}
	if len(d.Shapes) > 5 {
		fmt.Fprintf(p.output, "  ... and %d more shapes\n", len(d.Shapes)-5)
	}

	defaultChoice := "s"
	if d.Default.IsNewType {
		defaultChoice = "d"
	}

	var choice string
	for {
		choice = p.ask("[s]ame type? [d]ifferent? show [f]ull list?",
			defaultChoice, []string{"s", "d", "f"})
		if choice != "f" {
			break
		}
		for _, s := range d.Shapes {
			fmt.Fprintf(p.output, "  Shape %d (%d instances): %s\n",
				s.Index+1, s.Instances, strings.Join(s.Fields, ", "))
		}
	}

	d.Response = jsontypes.Response{IsNewType: choice == "d"}
	return nil
}

func cliShapeName(p *prompter, d *jsontypes.Decision) error {
	fmt.Fprintf(p.output, "  Shape %d: %s\n",
		d.ShapeIndex+1, strings.Join(fieldNames(d.Fields), ", "))

	name := p.askTypeName(
		fmt.Sprintf("  Name for shape %d?", d.ShapeIndex+1), d.Default.Name)
	d.Response = jsontypes.Response{Name: name}
	return nil
}

func cliNameCollision(p *prompter, d *jsontypes.Decision) error {
	fmt.Fprintf(p.output, "  Type %q already exists with overlapping fields: %s\n",
		d.Default.Name, strings.Join(d.ExistingFields, ", "))

	choice := p.ask(
		fmt.Sprintf("  [e]xtend %q with merged fields, or use a [d]ifferent name?", d.Default.Name),
		"e", []string{"e", "d"},
	)
	if choice == "e" {
		d.Response = jsontypes.Response{Extend: true, Name: d.Default.Name}
	} else {
		name := p.askTypeName("  New name?", d.Default.Name)
		d.Response = jsontypes.Response{Name: name}
	}
	return nil
}

func fieldNames(fields []jsontypes.FieldSummary) []string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.Name
	}
	return names
}
