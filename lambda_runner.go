//go:build lambda

package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog/log"
	"os"
	"strings"
)

func main() {
	lambda.Start(Handler)
}

func Handler(event events.APIGatewayCustomAuthorizerRequestTypeRequest) events.APIGatewayCustomAuthorizerResponse {
	jwksUrl := os.Getenv("JWKS_URL")
	if jwksUrl == "" {
		log.Error().Msg("JWKS_URL is not set")
		return generateDenyPolicy(event.MethodArn)
	}

	authHeader, ok := event.Headers["Authorization"]
	if !ok {
		log.Error().Msg("Authorization header not found")
		return generateDenyPolicy(event.MethodArn)
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	return authorize(tokenString, event.MethodArn, jwksUrl)
}
