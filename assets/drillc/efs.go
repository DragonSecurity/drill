package drillc

import (
	"embed"

	"github.com/DragonSecurity/drill/assets"
)

//go:embed static/*
var content embed.FS

func init() {
	assets.Register(content)
}
