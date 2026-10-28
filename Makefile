-include .env

SIGN_ID ?= -
BUMP ?= patch

export SIGN_ID DEV_SIGN_ID NOTARY_PROFILE SPARKLE_ACCOUNT SITE_URL R2_ACCOUNT_ID R2_BUCKET R2_PREFIX R2_TOKEN R2_SECRET R2_ACCESS_KEY_ID

.DEFAULT_GOAL := help
.PHONY: help dev dev-build test test-agent stop clean build dmg agent appicon release notarize publish publish-agent

help: ## List the commands
	@awk 'BEGIN {FS = ":.*## "} /^##@/ {printf "\n%s\n", substr($$0, 5)} /^[a-z0-9-]+:.*## / {printf "  make %-14s %s\n", $$1, $$2}' $(filter-out .env,$(MAKEFILE_LIST))

##@ Develop

dev: ## Build Rackpulse Dev and run it in the foreground. Ctrl-C stops it. Your installed Rackpulse keeps running
	@scripts/dev.sh

test: ## Run the HetznerKit unit tests
	cd packages/HetznerKit && xcrun swift test

test-agent: ## Vet and test the Linux agent
	cd agent && go vet ./... && go test ./...

stop: ## Stop Rackpulse Dev
	@pkill -x "Rackpulse Dev"; true

clean: stop ## Remove build output. Released versions in dist/Rackpulse-<version>/ stay
	rm -rf dist/Rackpulse.app dist/Rackpulse.dmg dist/dmg dist/feed dist/dev dist/dev-agent-version macos/.build packages/HetznerKit/.build

##@ Build

build: ## Build dist/Rackpulse.app, signed with SIGN_ID from .env or ad hoc
	@scripts/build.sh

dmg: build ## Build dist/Rackpulse.dmg with the drag-to-Applications window
	@scripts/dmg.sh

agent: ## Build the Linux agent into dist/agent/<version>
	@scripts/agent.sh

appicon: ## Rebuild macos/Resources/AppIcon.icns from AppIcon.svg
	@scripts/appicon.sh

dev-build: ## Build Rackpulse Dev and the dev agent, upload them to download/dev/ and agent/dev/. NOTARIZE=0 skips the download
	@scripts/dev-build.sh

##@ Release

release: ## Bump VERSION if it is tagged, notarize, publish, commit, tag, push, and create the GitHub release. BUMP=patch|minor|major
	@scripts/release.sh $(BUMP)

notarize: ## Sign, notarize and staple dist/Rackpulse-<version>/Rackpulse-<version>.dmg and write dist/appcast.xml
	@scripts/notarize.sh

publish: ## Upload the notarized disk images and dist/appcast.xml to R2
	@scripts/publish.sh

publish-agent: ## Upload the agent and install.sh to R2
	@scripts/publish-agent.sh
