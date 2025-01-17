## About

Silencer is a simple replacement for [fail2ban](https://www.fail2ban.org) written in Go.

After several hours of unsuccessful configuring of fail2ban I gave up and decided to build my own.

## Running
```

silencer [-config silencer.yaml] [-debug-rule]

```

## Configuration
The configuration is stored in YAML file. During startup silencer will
try to read "silencer.yaml" in the current directory. It is possible
to override location via `-config` option.


`log_file` section defines a collection of log files to monitor and
rules attached to them. Rules are used to match and extract IP address
from a log line.


Rule matching works by using a sequence of regexes to match and trim
line until only IP remains. If the regex fails to match, then the rule
is considered failed, and no more matching is performed. If regex
contains capture group, then log line will be replaced with the value
of capture group.


`env` section defines commons strings. All regexes are expanded using
these strings.


## Building & testing

```
git clone https://github.com/delamonpansie/silencer
cd silencer
go get github.com/golang/mock/mockgen
go generate ./...
go test ./...
go build .
```
