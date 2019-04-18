# Chartsec: Helm Chart security checker

[![CircleCI](https://circleci.com/gh/banzaicloud/chartsec.svg?style=svg)](https://circleci.com/gh/banzaicloud/chartsec)
[![Go Report Card](https://goreportcard.com/badge/github.com/banzaicloud/chartsec?style=flat-square)](https://goreportcard.com/report/github.com/banzaicloud/chartsec)
[![GoDoc](http://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/banzaicloud/chartsec)


## Why is everything in package `internal`?

While we believe this package is ultimately useful for anyone who work with third-party charts,
the API is not quite stable yet, the implementation might change,
so we decided to expose only what's necessary to use the core functionality to prevent ossification.


## License

Apache 2.0 License. Please see [License File](LICENSE) for more information.
