package authz

import rego.v1

default allow := false

allow if "admin" in input.roles

allow if {
	input.method == "GET"
	"reader" in input.roles
}
