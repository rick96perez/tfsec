package actions

import (
	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) (secrets []github.EnvironmentSecret) {

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_actions_environment_secret") {

			secret := github.EnvironmentSecret{
				Metadata:       types.Metadata{},
				Repository:     resource.GetAttributeValueAsStringOrDefault("repository", "", resource),
				Environment:    resource.GetAttributeValueAsStringOrDefault("environment", "", resource),
				SecretName:     resource.GetAttributeValueAsStringOrDefault("secret_name", "", resource),
				PlainTextValue: resource.GetAttributeValueAsStringOrDefault("plaintext_value", "", resource),
				EncryptedValue: resource.GetAttributeValueAsStringOrDefault("encrypted_value", "", resource),
			}

			secrets = append(secrets, secret)

		}
	}
	return secrets
}
