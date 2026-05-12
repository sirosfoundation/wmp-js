.PHONY: all build test lint clean help

all: lint test build ## Run lint, test, and build

build: ## Build the library
	npm run build

test: ## Run tests
	npm test

lint: ## Type-check and lint
	npm run lint

clean: ## Remove build artifacts
	rm -rf dist

help: ## List make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-24s\033[0m %s\n", $$1, $$2}'
