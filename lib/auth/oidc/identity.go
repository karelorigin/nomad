package oidc

import "github.com/hashicorp/nomad/nomad/structs"

type Identity struct {
	// Claims is the format of this Identity suitable for selection
	// with a binding rule.
	Claims interface{}

	// ClaimMappings is the format of this Identity suitable for interpolation in a
	// bind name within a binding rule.
	ClaimMappings map[string]string
}

func NewIdentity(
	authMethodConfig *structs.ACLAuthMethodConfig, authClaims *structs.ACLAuthClaims) *Identity {

	projectedVars := make(map[string]string)

	//
	for _, k := range authMethodConfig.ClaimMappings {
		projectedVars["value."+k] = ""
	}
	for k, val := range authClaims.Value {
		projectedVars["value."+k] = val
	}

	return &Identity{
		Claims:        authClaims,
		ClaimMappings: projectedVars,
	}
}
