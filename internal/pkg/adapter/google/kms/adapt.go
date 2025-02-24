package kms

import (
	"strconv"

	"github.com/aquasecurity/defsec/provider/google/kms"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) kms.KMS {
	return kms.KMS{
		KeyRings: adaptKeyRings(modules),
	}
}

func adaptKeyRings(modules block.Modules) []kms.KeyRing {
	var keyRings []kms.KeyRing
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_kms_key_ring") {
			var keys []kms.Key

			keyBlocks := module.GetReferencingResources(resource, "google_kms_crypto_key", "key_ring")
			for _, keyBlock := range keyBlocks {
				keys = append(keys, adaptKey(keyBlock))
			}
			keyRings = append(keyRings, kms.KeyRing{
				Keys: keys,
			})
		}
	}
	return keyRings
}

func adaptKey(resource *block.Block) kms.Key {
	rotationPeriodAttr := resource.GetAttribute("rotation_period")
	rotationStr := rotationPeriodAttr.Value().AsString()

	if rotationStr[len(rotationStr)-1:] != "s" {
		return kms.Key{}
	}
	seconds, err := strconv.Atoi(rotationStr[:len(rotationStr)-1])
	if err != nil {
		return kms.Key{}
	}

	return kms.Key{
		RotationPeriodSeconds: types.Int(seconds, *resource.GetMetadata()),
	}
}
