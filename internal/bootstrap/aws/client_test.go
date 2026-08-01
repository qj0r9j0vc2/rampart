package aws_test

import (
	"context"
	"testing"

	rampartaws "github.com/qj0r9j0vc2/rampart/internal/bootstrap/aws"
)

func TestNewClients(t *testing.T) {
	t.Parallel()

	iamClient, stsClient, err := rampartaws.NewClients(context.Background())
	if err != nil {
		t.Fatalf("NewClients() error = %v, want nil (loading the ambient AWS config shouldn't fail just because no credentials are configured)", err)
	}

	if iamClient == nil {
		t.Error("iamClient = nil, want a usable *iam.Client")
	}

	if stsClient == nil {
		t.Error("stsClient = nil, want a usable *sts.Client")
	}
}
