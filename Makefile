projectname?=bitswan

default: help

.PHONY: help
help: ## list makefile targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: build-frontend ## build golang binary
	@CGO_ENABLED=0 go build \
		-ldflags "-X main.version=$(shell git describe --abbrev=0 --tags) -w -s -extldflags '-static'" \
		-a \
		-o $(projectname)

# Bundle bailey's per-page React apps. esbuild + npm deps live under
# frontend/<name>/. Outputs go into internal/daemon/static/ so they're
# embedded into the daemon binary via go:embed at build time. Both the
# source and the built bundles are checked in — that way contributors
# don't need npm just to rebuild Go.
.PHONY: build-frontend
build-frontend: frontend/network-map/node_modules ## bundle bailey's React pages
	@esbuild frontend/network-map/index.jsx \
		--bundle --minify --target=es2022 --format=iife \
		--loader:.css=css \
		--define:process.env.NODE_ENV='"production"' \
		--outfile=internal/daemon/static/network-map.js

frontend/network-map/node_modules: frontend/network-map/package.json
	cd frontend/network-map && npm install --silent --no-audit --no-fund

.PHONY: install
install: ## install golang binary
	@go install -ldflags "-X main.version=$(shell git describe --abbrev=0 --tags)"

.PHONY: run
run: ## run the app
	@go run -ldflags "-X main.version=$(shell git describe --abbrev=0 --tags)"  main.go

.PHONY: bootstrap
bootstrap: ## install build deps
	go generate -tags tools tools/tools.go

PHONY: test
test: clean ## display test coverage
	go test --cover -parallel=1 -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | sort -rnk3
	
PHONY: clean
clean: ## clean up environment
	@rm -rf coverage.out dist/ $(projectname)

PHONY: cover
cover: ## display test coverage
	go test -v -race $(shell go list ./... | grep -v /vendor/) -v -coverprofile=coverage.out
	go tool cover -func=coverage.out

PHONY: fmt
fmt: ## format go files
	gofumpt -w .
	gci write .

PHONY: lint
lint: ## lint go files
	golangci-lint run -c .golang-ci.yml

.PHONY: pre-commit
pre-commit:	## run pre-commit hooks
	pre-commit run --all-files

