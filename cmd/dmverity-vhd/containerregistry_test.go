package main

import (
	"strings"
	"testing"

	"github.com/urfave/cli"
)

func TestImageCommandsExposeTokenFlags(t *testing.T) {
	for _, command := range []cli.Command{createVHDCommand, rootHashVHDCommand} {
		for _, flagName := range []string{bearerTokenFlag, identityTokenFlag} {
			found := false
			for _, commandFlag := range command.Flags {
				if strings.Split(commandFlag.GetName(), ",")[0] == flagName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s command does not expose --%s", command.Name, flagName)
			}
		}
	}
}

func TestRegistryAuthenticatorBearerToken(t *testing.T) {
	authenticator, err := registryAuthenticator("", "", "token-value", "")
	if err != nil {
		t.Fatalf("registryAuthenticator returned an error: %v", err)
	}

	config, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization returned an error: %v", err)
	}
	if config.RegistryToken != "token-value" {
		t.Fatalf("registry token = %q, want %q", config.RegistryToken, "token-value")
	}
}

func TestRegistryAuthenticatorIdentityToken(t *testing.T) {
	authenticator, err := registryAuthenticator("", "", "", "identity-token-value")
	if err != nil {
		t.Fatalf("registryAuthenticator returned an error: %v", err)
	}

	config, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization returned an error: %v", err)
	}
	if config.IdentityToken != "identity-token-value" {
		t.Fatalf("identity token = %q, want %q", config.IdentityToken, "identity-token-value")
	}
}

func TestRegistryAuthenticatorBasic(t *testing.T) {
	authenticator, err := registryAuthenticator("user", "pass", "", "")
	if err != nil {
		t.Fatalf("registryAuthenticator returned an error: %v", err)
	}

	config, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization returned an error: %v", err)
	}
	if config.Username != "user" || config.Password != "pass" {
		t.Fatalf("basic auth = %q/%q, want user/pass", config.Username, config.Password)
	}
}

func TestRegistryAuthenticatorRejectsPartialBasicAuth(t *testing.T) {
	for _, test := range []struct {
		name     string
		username string
		password string
	}{
		{name: "username only", username: "user"},
		{name: "password only", password: "pass"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := registryAuthenticator(test.username, test.password, "", "")
			if err == nil || !strings.Contains(err.Error(), "both username and password") {
				t.Fatalf("error = %v, want partial basic-auth validation", err)
			}
		})
	}
}

func TestRegistryAuthenticatorRejectsBearerWithBasicAuth(t *testing.T) {
	_, err := registryAuthenticator("user", "pass", "token-value", "")
	if err == nil || !strings.Contains(err.Error(), "cannot use token") {
		t.Fatalf("error = %v, want mutually exclusive auth validation", err)
	}
}

func TestRegistryAuthenticatorRejectsBearerWithIdentityToken(t *testing.T) {
	_, err := registryAuthenticator("", "", "token-value", "identity-token-value")
	if err == nil || !strings.Contains(err.Error(), "both bearer token and identity token") {
		t.Fatalf("error = %v, want mutually exclusive token validation", err)
	}
}
