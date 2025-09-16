//go:build wireinject
// +build wireinject

package main

import (
	"github.com/DragonSecurity/drill/internal/server"
	"github.com/DragonSecurity/drill/pkg/logger"
	"github.com/google/wire"
)

var providerSet = wire.NewSet(
	logger.ProviderSet,
	server.ProviderSet,
)

func CreateApp(cfg string) (*server.DrillServer, error) {
	panic(wire.Build(providerSet))
}
