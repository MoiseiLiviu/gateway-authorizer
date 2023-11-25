//go:build lambda

package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog/log"
	"strings"
)

func main() {
	lambda.Start(Handler)
}

func Handler(event events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	authHeader, ok := event.Headers["Authorization"]
	if !ok {
		log.Error().Msg("Authorization header not found")
		return generatePolicy("", "Deny", event.MethodArn), nil
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	return authorize(tokenString, event.MethodArn)
}
