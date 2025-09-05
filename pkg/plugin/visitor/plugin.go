package visitor

import (
	"context"
	"fmt"
	"net"

	v1 "github.com/DragonSecurity/drill/pkg/config/v1"
	"github.com/DragonSecurity/drill/pkg/vnet"
)

type PluginContext struct {
	Name           string
	Ctx            context.Context
	VnetController *vnet.Controller
	HandleConn     func(net.Conn)
}

// Creators is used for create plugins to handle connections.
var creators = make(map[string]CreatorFn)

type CreatorFn func(pluginCtx PluginContext, options v1.VisitorPluginOptions) (Plugin, error)

func Register(name string, fn CreatorFn) {
	if _, exist := creators[name]; exist {
		panic(fmt.Sprintf("plugin [%s] is already registered", name))
	}
	creators[name] = fn
}

func Create(pluginName string, pluginCtx PluginContext, options v1.VisitorPluginOptions) (p Plugin, err error) {
	if fn, ok := creators[pluginName]; ok {
		p, err = fn(pluginCtx, options)
	} else {
		err = fmt.Errorf("plugin [%s] is not registered", pluginName)
	}
	return
}

type Plugin interface {
	Name() string
	Start()
	Close() error
}
