# Chartsec: Helm Chart security checker

[![CircleCI](https://circleci.com/gh/banzaicloud/chartsec.svg?style=svg)](https://circleci.com/gh/banzaicloud/chartsec)
[![Go Report Card](https://goreportcard.com/badge/github.com/banzaicloud/chartsec?style=flat-square)](https://goreportcard.com/report/github.com/banzaicloud/chartsec)
[![GoDoc](http://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/banzaicloud/chartsec)

Chartsec scans a Helm chart for potential security vulnerabilities for it's user.
It's especially useful to check third-party charts before even decompressing them.


## Usage

Chartsec can be used both as a library and an executable.

Build the binary executable with the following command:

```bash
go get github.com/banzaicloud/chartsec/cmd/chartsec
```

Use it to check a chart package:

```bash
chartsec path/to/package.tgz
```

Or use it as a library in your project:

```go
package main

import (
	"os"
	
	"github.com/banzaicloud/chartsec"
)

func main() {
    file, err := os.Open("path/to/package.tgz")
    if err != nil {
        panic(err)
    }

    scanner := chartsec.NewDefaultChartScanner()

    err = scanner.Scan(file)
    if err != nil {
    	panic(err)
    }
}
```


## Security checks

- Compressed archive does not exceed 10MB
- Decompressed archive does not exceed 10MB
- Markdown files do not contain malicious content (html script, etc)


## Why is everything in package `internal`?

While we believe this package is ultimately useful for anyone who work with third-party charts,
the API is not quite stable yet, the implementation might change,
so we decided to expose only what's necessary to use the core functionality to prevent ossification.


## License

Apache 2.0 License. Please see [License File](LICENSE) for more information.
