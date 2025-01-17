package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"regexp"
	"time"

	"github.com/nxadm/tail"

	"github.com/delamonpansie/silencer/config"
	"github.com/delamonpansie/silencer/filter"
	"github.com/delamonpansie/silencer/set"
)

type blockRequest struct {
	ip       net.IP
	duration time.Duration
}

func worker(blocker filter.Blocker, whitelist []net.IPNet) chan<- blockRequest {
	c := make(chan blockRequest, 16)
	go func() {
		timer := time.NewTimer(0)
		active := set.NewSet()
		for {
		next:
			select {
			case b := <-c:
				for _, subnet := range whitelist {
					if subnet.Contains(b.ip) {
						goto next
					}
				}

				unseen := active.Insert(b.ip, b.duration)
				if unseen {
					log.Printf("blocking %s for %v", b.ip, b.duration)
					blocker.Block(b.ip)
				}
			case <-timer.C:
				for _, ip := range active.Expire() {
					log.Printf("unblock %s", ip)
					blocker.Unblock(ip)
				}
			}

			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if deadline := active.Deadline(); !deadline.IsZero() {
				timer.Reset(deadline.Sub(time.Now()))
			}
		}
	}()
	return c
}

////////////////////////////////////////////////////////////////////////////////

type rule struct {
	name     string
	re       []*regexp.Regexp
	duration time.Duration
}

func newRule(name string, src []string, duration time.Duration) rule {
	re := make([]*regexp.Regexp, len(src))
	for i, s := range src {
		re[i] = regexp.MustCompile(s)
	}
	return rule{name, re, duration}
}

var debugRule = flag.String("debug-rule", "", "enable rule matching logs")

func (rule *rule) match(line string) (ip net.IP, err error) {
	if *debugRule != "" {
		fmt.Printf("matching rule %q\n", rule.name)
		defer func() {
			switch {
			case ip != nil:
				fmt.Printf(" success %q\n", ip.String())
			case err != nil:
				fmt.Printf(" failure %s\n", err.Error())
			default:
				fmt.Printf(" no match\n")
			}
		}()
	}

	src := line
	for i, re := range rule.re {
		m := re.FindStringSubmatch(src)
		if *debugRule != "" {
			fmt.Printf(" [%d] %q\n", i, src)
			fmt.Printf("  re %s\n", re)
			fmt.Printf("  => %q\n", m)
		}
		switch len(m) {
		case 0:
			return nil, nil
		case 1:
			continue
		case 2:
			src = m[1]
		default:
			return nil, fmt.Errorf("rule %s, unexpected matches %q in line %q:",
				rule.name, m, line)
		}
	}
	ip = net.ParseIP(src).To4()
	if ip == nil {
		return nil, fmt.Errorf("rule %s, invalid ip %q", rule.name, src)
	}
	return
}

///////////////////////////////////////////////////////////////////////////////

func tailLog(filename string) <-chan *tail.Line {
	config := tail.Config{
		Follow: true,
		ReOpen: true,
	}
	t, err := tail.TailFile(filename, config)
	if err != nil {
		log.Fatal(err)
	}

	return t.Lines
}

func run(filename string, rules []rule, block chan<- blockRequest) {
	for line := range tailLog(filename) {
		if line.Err != nil {
			log.Println(line.Err)
			continue
		}

		for _, rule := range rules {
			ip, err := rule.match(line.Text)
			if ip != nil {
				block <- blockRequest{ip, rule.duration}
			}
			if err != nil {
				log.Println(err.Error())
			}
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////

func main() {
	flag.Parse()
	cfg := config.Load()

	if *debugRule != "" {
		var matchedLogFile []config.LogFile
		for _, logFile := range cfg.LogFile {
			var matchedRule []config.Rule
			for _, rule := range logFile.Rule {
				if rule.Name == *debugRule {
					matchedRule = append(matchedRule, rule)
				}
			}
			if len(matchedRule) > 0 {
				logFile.Rule = matchedRule
				matchedLogFile = append(matchedLogFile, logFile)
			}
		}
		if len(matchedLogFile) == 0 {
			log.Fatal("no matching rules found")
		}
		cfg.LogFile = matchedLogFile
	}

	var blocker filter.Blocker
	switch {
	case *debugRule != "":
		blocker = filter.NewDummy()
	case cfg.Filter.IPTables != nil:
		if blocker != nil {
			log.Fatal("exactly one filter must be configured")
		}
		blocker = filter.NewIPtables(cfg.Filter.IPTables.Chain)
	case cfg.Filter.IPSet != nil:
		if blocker != nil {
			log.Fatal("exactly one filter must be configured")
		}
		blocker = filter.NewIPset(cfg.Filter.IPSet.Set)
	case cfg.Filter.Cloudflare != nil:
		if blocker != nil {
			log.Fatal("exactly one filter must be configured")
		}
		blocker = filter.NewCloudflare(cfg.Filter.Cloudflare.Account, cfg.Filter.Cloudflare.ListId, cfg.Filter.Cloudflare.AuthEmail, cfg.Filter.Cloudflare.AuthKey)
	case cfg.Filter.Fastly != nil:
		if blocker != nil {
			log.Fatal("exactly one filter must be configured")
		}
		blocker = filter.NewFastly(cfg.Filter.Fastly.ApiKey, cfg.Filter.Fastly.ServiceID, cfg.Filter.Fastly.ACLID)
	default:
		panic("not reached")
	}
	block := worker(blocker, cfg.Whitelist)

	for _, ip := range blocker.List() {
		block <- blockRequest{ip: ip, duration: cfg.Duration / 2}
	}

	for _, logFile := range cfg.LogFile {
		rules := make([]rule, len(logFile.Rule))
		for i, ruleConfig := range logFile.Rule {
			rules[i] = newRule(ruleConfig.Name, ruleConfig.Re, ruleConfig.Duration)
		}

		go run(logFile.FileName, rules, block)
	}

	select {}
}
