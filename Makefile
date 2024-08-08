PROJECT_NAME := "passkey"
PKG := "github.com/egregors/$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)

## Common tasks

.PHONY: dep
dep: ## Dep stuff we need
	go install github.com/caddyserver/caddy/v2/cmd/caddy@v2.8.4


.PHONY: lint
lint: ## Lint the files
	golangci-lint run ./... --timeout 1m -c .golangci.yml

.PHONY: test
test: ## Run unittests
	@go test -short ${PKG_LIST} -count=1

.PHONY: run
run:  ## Run example project
	@go run _example/*

.PHONY: caddy-run
caddy-run: ## Caddy runner
	caddy run --config caddy_config_caddyfile --adapter caddyfile

.PHONY: gen
gen:  ## Generate mocks
	@mockery

.PHONY: update-go-deps
update-go-deps:  ## Updating Go dependencies
	@echo ">> updating Go dependencies"
	@for m in $$(go list -mod=readonly -m -f '{{ if and (not .Indirect) (not .Main)}}{{.Path}}{{end}}' all); do \
		go get $$m; \
	done
	go mod tidy
ifneq (,$(wildcard vendor))
	go mod vendor
endif

## Help

.PHONY: help
help:  ## Show help message
	@IFS=$$'\n' ; \
	help_lines=(`fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/:/'`); \
	printf "%s\n\n" "Usage: make [task]"; \
	printf "%-20s %s\n" "task" "help" ; \
	printf "%-20s %s\n" "------" "----" ; \
	for help_line in $${help_lines[@]}; do \
		IFS=$$':' ; \
		help_split=($$help_line) ; \
		help_command=`echo $${help_split[0]} | sed -e 's/^ *//' -e 's/ *$$//'` ; \
		help_info=`echo $${help_split[2]} | sed -e 's/^ *//' -e 's/ *$$//'` ; \
		printf '\033[36m'; \
		printf "%-20s %s" $$help_command ; \
		printf '\033[0m'; \
		printf "%s\n" $$help_info; \
	done