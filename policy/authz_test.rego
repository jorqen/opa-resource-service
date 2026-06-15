package authz_test

import rego.v1

import data.authz

test_admin_allowed_on_any_method if {
	authz.allow with input as {"method": "DELETE", "path": "/resource", "roles": ["admin"]}
}

test_reader_allowed_on_get if {
	authz.allow with input as {"method": "GET", "path": "/resource", "roles": ["reader"]}
}

test_reader_denied_on_non_get if {
	not authz.allow with input as {"method": "POST", "path": "/resource", "roles": ["reader"]}
}

test_unknown_role_denied if {
	not authz.allow with input as {"method": "GET", "path": "/resource", "roles": ["editor"]}
}

test_no_roles_denied if {
	not authz.allow with input as {"method": "GET", "path": "/resource", "roles": []}
}
