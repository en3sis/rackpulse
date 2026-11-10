package security

import (
	"reflect"
	"strings"
	"testing"
)

func deps(pairs ...string) []Dependency {
	result := []Dependency{}
	for _, pair := range pairs {
		name, version, _ := strings.Cut(pair, " ")
		result = append(result, Dependency{Name: name, Version: version})
	}
	return result
}

func TestLockfileParsers(t *testing.T) {
	cases := []struct {
		fixture string
		parse   func([]byte) ([]Dependency, error)
		want    []Dependency
	}{
		{"npm-v1.json", parseNpmLock, deps("debug 2.6.9", "debug 4.3.4", "express 4.17.1", "lodash 4.17.20", "string-width 4.2.3")},
		{"npm-v3.json", parseNpmLock, deps("@babel/core 7.22.0", "debug 2.6.9", "debug 4.3.4", "lodash 4.17.20", "string-width 4.2.3")},
		{"pnpm-v5.yaml", parsePnpmLock, deps("@babel/core 7.22.0", "react 18.2.0", "react-dom 18.2.0")},
		{"pnpm-v6.yaml", parsePnpmLock, deps("@babel/core 7.22.0", "@types/node 20.10.0", "js-tokens 4.0.0", "react 18.2.0", "react-dom 18.2.0")},
		{"pnpm-v9.yaml", parsePnpmLock, deps("@babel/core 7.22.0", "js-tokens 4.0.0", "react 18.2.0", "react-dom 18.2.0")},
		{"pnpm-multi.yaml", parsePnpmLock, deps("@pnpm/exe 9.12.0", "react 18.2.0", "typescript 5.6.3")},
		{"yarn-classic.lock", parseYarnLock, deps("@babel/code-frame 7.12.13", "lodash 4.17.20", "minimist 1.2.5")},
		{"yarn-berry.lock", parseYarnLock, deps("@babel/code-frame 7.12.13", "lodash 4.17.20", "resolve 1.22.1")},
		{"requirements.txt", parseRequirements, deps("django 4.2.1", "flask-sqlalchemy 3.0.5", "requests 2.31.0", "zope-interface 6.0")},
		{"poetry.lock", parsePythonLock, deps("certifi 2023.7.22", "jinja2 3.1.2")},
		{"uv.lock", parsePythonLock, deps("anyio 4.4.0", "idna 3.7")},
		{"Pipfile.lock", parsePipfileLock, deps("django 4.2.1", "pytest 7.4.0", "requests 2.31.0")},
		{"go.mod", parseGoMod, deps("github.com/docker/docker 24.0.7+incompatible", "golang.org/x/net 0.23.0", "golang.org/x/text 0.14.0")},
		{"Cargo.lock", parseCargoLock, deps("serde 1.0.188", "time 0.1.45")},
		{"composer.lock", parseComposerLock, deps("guzzlehttp/guzzle 7.8.0", "phpunit/phpunit 10.3.2", "symfony/http-kernel 6.3.4")},
		{"Gemfile.lock", parseGemfileLock, deps("actionpack 7.0.4", "nokogiri 1.13.10", "racc 1.6.0", "rack 2.2.4")},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			parsed, err := c.parse(readFixture(t, "lockfiles/"+c.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if got := uniqueDependencies(parsed); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestLockfileParsersRejectInvalidJSON(t *testing.T) {
	for _, parse := range []func([]byte) ([]Dependency, error){parseNpmLock, parsePipfileLock, parseComposerLock} {
		if _, err := parse([]byte("{not json")); err == nil {
			t.Fatal("invalid JSON must fail")
		}
	}
}
