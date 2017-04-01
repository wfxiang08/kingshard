// Copyright 2016 The kingshard Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/flike/kingshard/config"
	"github.com/flike/kingshard/core/hack"
	"github.com/flike/kingshard/proxy/server"
	"github.com/flike/kingshard/web"
	log "github.com/wfxiang08/cyutils/utils/rolling_log"
)

var configFile *string = flag.String("config", "/etc/ks.yaml", "kingshard config file")
var logLevel *string = flag.String("log-level", "", "log level [debug|info|warn|error], default error")
var version *bool = flag.Bool("v", false, "the version of kingshard")

const (
	sqlLogName = "sql.log"
	sysLogName = "sys.log"
	MaxLogSize = 1024 * 1024 * 1024
)

const banner string = `我是kingshard`

func main() {
	fmt.Print(banner)
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	fmt.Printf("Git commit:%s\n", hack.Version)
	fmt.Printf("Build time:%s\n", hack.Compile)
	if *version {
		return
	}
	if len(*configFile) == 0 {
		fmt.Println("must use a config file")
		return
	}

	// 解析配置文件
	cfg, err := config.ParseConfigFile(*configFile)
	if err != nil {
		fmt.Printf("parse config file error:%v\n", err.Error())
		return
	}

	// 设置Log文件
	//when the log file size greater than 1GB, kingshard will generate a new file
	if len(cfg.LogPath) != 0 {

	}

	if *logLevel != "" {
		setLogLevel(*logLevel)
	} else {
		setLogLevel(cfg.LogLevel)
	}

	var svr *server.Server
	var apiSvr *web.ApiServer

	// 最核心的逻辑： Server
	svr, err = server.NewServer(cfg)

	if err != nil {
		log.ErrorErrorf(err, "server.NewServer failed")
		return
	}
	apiSvr, err = web.NewApiServer(cfg, svr)
	if err != nil {
		log.ErrorErrorf(err, "web.NewApiServer failed")
		svr.Close()
		return
	}

	// 监听signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGPIPE,
	)

	go func() {
		for {
			// 异步处理信号
			sig := <-sc
			if sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == syscall.SIGQUIT {
				log.Printf("receive quit signal")

				// 关闭Server, 然后: srv.run就结束
				svr.Close()
			} else if sig == syscall.SIGPIPE {
				log.Printf("Ignore broken pipe signal")
			}
		}
	}()
	// 对外提供API服务
	go apiSvr.Run()

	// 提供mysql server的服务
	svr.Run()
}

func setLogLevel(level string) {
	//switch strings.ToLower(level) {
	//case "debug":
	//	golog.GlobalSysLogger.SetLevel(golog.LevelDebug)
	//case "info":
	//	golog.GlobalSysLogger.SetLevel(golog.LevelInfo)
	//case "warn":
	//	golog.GlobalSysLogger.SetLevel(golog.LevelWarn)
	//case "error":
	//	golog.GlobalSysLogger.SetLevel(golog.LevelError)
	//default:
	//	golog.GlobalSysLogger.SetLevel(golog.LevelError)
	//}
}
