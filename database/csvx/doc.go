// Package csvx provides nullable row-oriented data types that bridge
// CSV, JSON, and SQL. Each type implements MarshalCSV/UnmarshalCSV,
// MarshalJSON/UnmarshalJSON, and driver.Value/Scan so the same struct
// can be read from a sheet, written to a file, and scanned from a database.
//
// It also provides generic Parse/Serialize functions for CSV, TSV, JSON,
// and JSONL, delimiter-specific string and integer slices, plus text
// normalization helpers (NormalizeEmail, NormalizePhone).
package csvx
