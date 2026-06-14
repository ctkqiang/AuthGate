package aws

import (
	"authgate/internal/utilities"
	"context"

	"github.com/aws/aws-lambda-go/lambda"
)

func InitializeLambdaService() {
	lambda.Start(LambdaHandleRequest)
}

func LambdaHandleRequest(ctx context.Context) (string, error) {
	utilities.LogProgress(
		"Lambda",
		"HandleRequest",
		"Start",
	)

	return "200", nil
}
