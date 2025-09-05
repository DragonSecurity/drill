package main

import (
	_ "github.com/DragonSecurity/drill/assets/drills"
	_ "github.com/DragonSecurity/drill/pkg/metrics"
	"github.com/DragonSecurity/drill/pkg/util/system"
)

func main() {
	system.EnableCompatibilityMode()
	Execute()
}
