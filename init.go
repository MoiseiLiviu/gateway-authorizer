package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/rs/zerolog/log"
)

func authorize(tokenString string, methodArn string, jwksUrl string) events.APIGatewayCustomAuthorizerResponse {
	authorizer, err := NewAuthorizer(jwksUrl)
	if err != nil {
		log.Err(err).Msg("Failed to create authorizer")
		return generateDenyPolicy(methodArn)
	}

	err = authorizer.Execute(tokenString)
	if err != nil {
		log.Err(err).Msg("Failed to validate token")
		return generateDenyPolicy(methodArn)
	}

	return generateAllowPolicy("Allow", methodArn)
}

func generateAllowPolicy(resource, token string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := generatePolicy("Allow", resource)

	authResponse.Context = map[string]interface{}{
		"Token": token,
	}

	return authResponse
}

func generateDenyPolicy(resource string) events.APIGatewayCustomAuthorizerResponse {
	return generatePolicy("Deny", resource)
}

func generatePolicy(effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	var authResponse events.APIGatewayCustomAuthorizerResponse
	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	return authResponse
}
