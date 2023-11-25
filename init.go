package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"io"
	"math/big"
	"net/http"
	"os"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

func authorize(tokenString string, methodArn string) (events.APIGatewayCustomAuthorizerResponse, error) {
	jwksUrl := os.Getenv("JWKS_URL")
	if jwksUrl == "" {
		log.Err(errors.New("JWKS_URL is not set")).Msg("JWKS_URL is not set")
		return generatePolicy("", "Deny", methodArn), nil
	}

	jwks, err := getCognitoJwks(jwksUrl)
	if err != nil {
		log.Err(err).Msg("Failed to get JWKS")
		return generatePolicy("", "Deny", methodArn), nil
	}

	token, err := validateToken(tokenString, jwks)
	if err != nil {
		log.Err(err).Msg("Failed to validate token")
		return generatePolicy("", "Deny", methodArn), nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return generatePolicy("", "Deny", methodArn), nil
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return generatePolicy("", "Deny", methodArn), nil
	}

	return generatePolicy(userID, "Allow", methodArn), nil
}

func validateToken(tokenString string, jwks *Jwks) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify 'alg' is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		for _, key := range jwks.Keys {
			if key.Kid == kid {
				pemEncodedKey, err := getPemEncodedKey(key)
				if err != nil {
					return nil, err
				}

				return jwt.ParseRSAPublicKeyFromPEM([]byte(pemEncodedKey))
			}
		}

		return nil, fmt.Errorf("key not found")
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

func getPemEncodedKey(jwk JSONWebKeys) (string, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return "", err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return "", err
	}

	eValue := new(big.Int).SetBytes(eBytes).Int64()

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(eValue),
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	pemEncodedKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(pemEncodedKey), nil
}

func getCognitoJwks(jwksUrl string) (*Jwks, error) {
	resp, err := http.Get(jwksUrl)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get JWKS: %s", body)
	}

	var jwks Jwks
	err = json.Unmarshal(body, &jwks)
	return &jwks, err
}

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}
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

	authResponse.Context = map[string]interface{}{
		"UserID": principalID,
	}

	return authResponse
}
