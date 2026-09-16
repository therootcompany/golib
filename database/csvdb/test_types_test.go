package csvdb

import "github.com/therootcompany/golib/database/csvx"

type testRuleRow struct {
	Email string `json:"email"`
}

type identityRow struct {
	Email csvx.Text `json:"email"`
	Phone csvx.Text `json:"phone"`
}
