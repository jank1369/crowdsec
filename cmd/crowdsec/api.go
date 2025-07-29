package main

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

/*启动了一个完整的CrowdSec LAPI服务，包括：
数据管理：数据库定时清理、指标收集(数据清理
API服务：HTTP服务器、RESTful接口(API服务)
通信服务：与中央API和控制台的双向通信(通信服务)
插件系统：通知和扩展功能(插件系统)
这些服务协同工作，为CrowdSec提供了完整的威胁检测、防护和协作防御能力。
*/

func initAPIServer(ctx context.Context, cConfig *csconfig.Config) (*apiserver.APIServer, error) {
	if cConfig.API.Server.OnlineClient == nil || cConfig.API.Server.OnlineClient.Credentials == nil {
		log.Info("push and pull to Central API disabled")
	}

	// 初始化api服务
	apiServer, err := apiserver.NewServer(ctx, cConfig.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	// 初始化插件
	err = apiServer.InitPlugins(ctx, cConfig, &pluginBroker)
	if err != nil {
		return nil, err
	}

	// 初始化控制器
	err = apiServer.InitController()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	return apiServer, nil
}

// 启动API服务
func serveAPIServer(apiServer *apiserver.APIServer) {
	apiReady := make(chan bool, 1)

	apiTomb.Go(func() error {
		defer trace.CatchPanic("crowdsec/serveAPIServer")

		go func() {
			defer trace.CatchPanic("crowdsec/runAPIServer")
			log.Debugf("serving API after %s ms", time.Since(crowdsecT0))

			if err := apiServer.Run(apiReady); err != nil {
				log.Fatal(err)
			}
		}()

		pluginTomb.Go(func() error {
			pluginBroker.Run(&pluginTomb)
			return nil
		})

		<-apiTomb.Dying() // lock until go routine is dying
		pluginTomb.Kill(nil)
		log.Infof("serve: shutting down api server")

		return apiServer.Shutdown()
	})
	<-apiReady
}
