package apitests

import (
	"net/url"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	capOIDC "github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/nomad/api"
	"github.com/hashicorp/nomad/ci"
	"github.com/shoenig/test/must"
)

func TestACLOIDC_GetAuthURL(t *testing.T) {
	ci.Parallel(t)

	testClient, testServer, _ := makeACLClient(t, nil, nil)
	defer testServer.Stop()

	// Set up the test OIDC provider.
	oidcTestProvider := capOIDC.StartTestProvider(t)
	defer oidcTestProvider.Stop()
	oidcTestProvider.SetAllowedRedirectURIs([]string{"http://127.0.0.1:4649/oidc/callback"})

	// Generate and upsert an ACL auth method for use. Certain values must be
	// taken from the cap OIDC provider just like real world use.
	mockedAuthMethod := api.ACLAuthMethod{
		Name:          "api-test-auth-method",
		Type:          api.ACLAuthMethodTypeOIDC,
		TokenLocality: api.ACLAuthMethodTokenLocalityGlobal,
		MaxTokenTTL:   10 * time.Hour,
		Default:       true,
		Config: &api.ACLAuthMethodConfig{
			OIDCDiscoveryURL:    oidcTestProvider.Addr(),
			OIDCClientID:        "mock",
			OIDCClientSecret:    "verysecretsecret",
			BoundAudiences:      []string{"mock"},
			AllowedRedirectURIs: []string{"http://127.0.0.1:4649/oidc/callback"},
			DiscoveryCaPem:      []string{oidcTestProvider.CACert()},
			SigningAlgs:         []string{"ES256"},
			ClaimMappings:       map[string]string{"foo": "bar"},
			ListClaimMappings:   map[string]string{"foo": "bar"},
		},
	}

	createdAuthMethod, writeMeta, err := testClient.ACLAuthMethods().Create(&mockedAuthMethod, nil)
	must.NoError(t, err)
	must.NotNil(t, createdAuthMethod)
	assertWriteMeta(t, writeMeta)

	// Generate and make the request.
	authURLRequest := api.ACLOIDCAuthURLRequest{
		AuthMethodName: createdAuthMethod.Name,
		RedirectURI:    createdAuthMethod.Config.AllowedRedirectURIs[0],
		ClientNonce:    "fpSPuaodKevKfDU3IeXb",
	}

	authURLResp, writeMeta, err := testClient.ACLOIDC().GetAuthURL(&authURLRequest, nil)
	must.NoError(t, err)
	assertWriteMeta(t, writeMeta)

	// The response URL comes encoded, so decode this and check we have each
	// component we expect.
	escapedURL, err := url.PathUnescape(authURLResp.AuthURL)
	must.NoError(t, err)
	must.StrContains(t, escapedURL, "/authorize?client_id=mock")
	must.StrContains(t, escapedURL, "&nonce=fpSPuaodKevKfDU3IeXa")
	must.StrContains(t, escapedURL, "&redirect_uri=http://127.0.0.1:4649/oidc/callback")
	must.StrContains(t, escapedURL, "&response_type=code")
	must.StrContains(t, escapedURL, "&scope=openid")
	must.StrContains(t, escapedURL, "&state=st_")
}

func TestACLOIDC_CompleteAuth(t *testing.T) {
	ci.Parallel(t)

	testClient, testServer, _ := makeACLClient(t, nil, nil)
	defer testServer.Stop()

	// Set up the test OIDC provider.
	oidcTestProvider := capOIDC.StartTestProvider(t)
	defer oidcTestProvider.Stop()
	oidcTestProvider.SetAllowedRedirectURIs([]string{"http://127.0.0.1:4649/oidc/callback"})

	// Generate and upsert an ACL auth method for use. Certain values must be
	// taken from the cap OIDC provider just like real world use.
	mockedAuthMethod := api.ACLAuthMethod{
		Name:          "api-test-auth-method",
		Type:          api.ACLAuthMethodTypeOIDC,
		TokenLocality: api.ACLAuthMethodTokenLocalityGlobal,
		MaxTokenTTL:   10 * time.Hour,
		Default:       true,
		Config: &api.ACLAuthMethodConfig{
			OIDCDiscoveryURL:    oidcTestProvider.Addr(),
			OIDCClientID:        "mock",
			OIDCClientSecret:    "verysecretsecret",
			BoundAudiences:      []string{"mock"},
			AllowedRedirectURIs: []string{"http://127.0.0.1:4649/oidc/callback"},
			DiscoveryCaPem:      []string{oidcTestProvider.CACert()},
			SigningAlgs:         []string{"ES256"},
			ClaimMappings:       map[string]string{"foo": "bar"},
			ListClaimMappings:   map[string]string{"foo": "bar"},
		},
	}

	createdAuthMethod, writeMeta, err := testClient.ACLAuthMethods().Create(&mockedAuthMethod, nil)
	must.NoError(t, err)
	must.NotNil(t, createdAuthMethod)
	assertWriteMeta(t, writeMeta)

	// Set our custom data and some expected values, so we can make the call
	// and use the test provider.
	oidcTestProvider.SetExpectedAuthNonce("fpSPuaodKevKfDU3IeXb")
	oidcTestProvider.SetExpectedAuthCode("codeABC")
	oidcTestProvider.SetCustomAudience("mock")
	oidcTestProvider.SetExpectedState("st_someweirdstateid")
	oidcTestProvider.SetCustomClaims(map[string]interface{}{"azp": "mock"})

	// Generate and make the request.
	authURLRequest := api.ACLOIDCCompleteAuthRequest{
		AuthMethodName: createdAuthMethod.Name,
		RedirectURI:    createdAuthMethod.Config.AllowedRedirectURIs[0],
		ClientNonce:    "fpSPuaodKevKfDU3IeXb",
		State:          "st_someweirdstateid",
	}

	completeAuthResp, writeMeta, err := testClient.ACLOIDC().CompleteAuth(&authURLRequest, nil)
	must.NoError(t, err)
	assertWriteMeta(t, writeMeta)
	spew.Dump(completeAuthResp)
}
