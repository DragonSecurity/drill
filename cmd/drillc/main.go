package main

import (
	"github.com/DragonSecurity/drill/cmd/drillc/sub"
	"github.com/DragonSecurity/drill/pkg/util/system"
)

func main() {
	system.EnableCompatibilityMode()
	sub.Execute()
}
