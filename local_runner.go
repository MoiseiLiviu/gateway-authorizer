//go:build local

package main

import (
	"github.com/rs/zerolog/log"
)

func main() {
	policy, err := authorize("eyJraWQiOiJpNmdRaXpQNU9Oak42Ynpydys2XC9UMHpvMTA2b29VRVAzcERHWEE0a1VPQT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2NDYzZWU2Ny02M2Y2LTRmN2EtODJlNi00MzVlZDAxNWNjNzciLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtY2VudHJhbC0xLmFtYXpvbmF3cy5jb21cL2V1LWNlbnRyYWwtMV9rZzZYdExuY00iLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiI1cWZsMGo2aXVjaXVxa3RkbTEzcDFrYXVndCIsIm9yaWdpbl9qdGkiOiIzZjBmMTUxNS1iNWVhLTQzNmItODQ3Mi0wNmIwMjBkNGVhMjYiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6InBob25lIG9wZW5pZCBlbWFpbCIsImF1dGhfdGltZSI6MTcwMDgxOTYyNCwiZXhwIjoxNzAwODIzMjI0LCJpYXQiOjE3MDA4MTk2MjQsImp0aSI6IjM4YzJjODFmLWY5NzEtNDA1Yi1iYjE4LTFkNGQ0NGIwYWE3MSIsInVzZXJuYW1lIjoiTW9pc2VpTCJ9.S7uxS4WO3ohBWyt_vTL3nn9bnV6R4jztfhhsPHLKD5z8-NMEULJf-j9W369lZVF0k2UlhByF30NMUbATVI9Ct4hgX19P7afI4gr2TavCqTnScHFItpP4Xy-7f8S_W640GpuJKmplCsf7QHDdSWTQcFda2gisdu63rVVMwhAVTC8Ii7hxaHqQ--DvojbVshosXQJn0mgJ4SYkQevD_EQsot7-xBX891JOSzjJCMUQo0UPx-6GXT1oLCJAcU3csNQ6vIEwmbsuaGJa2V7EQos5GnqzlRjfAto7bkPgyWFN5WD7Qx81Rf00_upKyuV1S7QN2wRZ6suA9wTfcEKKGUdCHQ",
		"dwadwadwawddaw")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to authorize")
	}
	log.Info().Msgf("Policy: %v", policy)
}