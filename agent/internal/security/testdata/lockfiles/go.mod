module github.com/acme/app

go 1.22

toolchain go1.22.5

require github.com/gorilla/mux v1.8.0

require (
	golang.org/x/net v0.17.0
	golang.org/x/text v0.13.0 // indirect
	github.com/docker/docker v24.0.7+incompatible
)

replace (
	github.com/old/thing v1.0.0 => github.com/new/thing v1.1.0
)

exclude github.com/bad/thing v0.1.0

replace golang.org/x/net v0.17.0 => golang.org/x/net v0.23.0

replace (
	github.com/gorilla/mux => ../mux
	golang.org/x/text => golang.org/x/text v0.14.0
	github.com/docker/docker v1.0.0 => github.com/docker/docker v99.0.0
)
