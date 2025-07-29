package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// 启动解析器(日志解析引擎，负责将原始日志事件转换为结构化数据)
/*
	1. 通过chan 接收input event
	2. 如果是应用安全事件直接输出
	3. 如果事件module为空则报错
	4. 指标统计
	5. 解析日志， 将原始日志转换为结构化数据
	6. 指标统计，输出
*/

func runParse(input chan types.Event, output chan types.Event, parserCTX parser.UnixParserCtx, nodes []parser.Node) error {
	for {
		select {
		case <-parsersTomb.Dying():
			log.Infof("Killing parser routines")
			return nil
		case event := <-input:
			// 如果事件不需要处理，则跳过
			if !event.Process {
				continue
			}
			/*Application security engine is going to generate 2 events:
			- one that is treated as a log and can go to scenarios
			- another one that will go directly to LAPI*/
			// 如果事件是应用安全事件，则直接输出
			if event.Type == types.APPSEC {
				outputEventChan <- event
				continue
			}

			// 如果事件module为空则报错
			if event.Line.Module == "" {
				log.Errorf("empty event.Line.Module field, the acquisition module must set it ! : %+v", event.Line)
				continue
			}
			// 指标统计
			globalParserHits.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Inc()

			// 开始解析
			startParsing := time.Now()
			/* parse the log using magic */
			// 解析日志， 将原始日志转换为结构化数据
			parsed, err := parser.Parse(parserCTX, event, nodes)
			if err != nil {
				log.Errorf("failed parsing: %v", err)
			}
			elapsed := time.Since(startParsing)

			// 指标统计
			globalParsingHistogram.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Observe(elapsed.Seconds())
			if !parsed.Process {
				globalParserHitsKo.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Inc()
				log.Debugf("Discarding line %+v", parsed)
				continue
			}
			// 指标统计
			globalParserHitsOk.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Inc()
			if parsed.Whitelisted {
				log.Debugf("event whitelisted, discard")
				continue
			}

			// 输出解析结果
			output <- parsed
		}
	}
}
