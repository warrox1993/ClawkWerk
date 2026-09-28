# ClawkWerk — cibles de développement et de build.
# Le build est STATIQUE (CGo-free) et REPRODUCTIBLE (-trimpath, buildid vidé) :
# indispensable pour un binaire qui touche des réseaux clients.

GO      ?= go
PKG     := ./...
BINDIR  := bin
LDFLAGS := -buildid=
BUILDFLAGS := -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all fmt vet staticcheck test fuzz vuln build build-consultant verify check clean

all: check build

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo 'exécuter: gofmt -w .' && exit 1)

vet:
	$(GO) vet $(PKG)

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest $(PKG)

test:
	$(GO) test -race $(PKG)

# Fuzzing court des normaliseurs (ils parsent des sorties d'équipements).
fuzz:
	$(GO) test -run='^$$' -fuzz='^FuzzNormalizers$$' -fuzztime=30s ./internal/cyfun/controls/

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

verify:
	$(GO) mod verify

# check = tout ce que la CI exige, en local.
check: fmt vet staticcheck test vuln verify

# Binaire APPLIANCE (clé bootable) : statique, reproductible, INDÉPENDANT de
# SQLite (l'historique ne vit jamais sur la clé). C'est le build par défaut.
build:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=0 $(GO) build $(BUILDFLAGS) -o $(BINDIR)/orchestrator ./cmd/orchestrator
	CGO_ENABLED=0 $(GO) build $(BUILDFLAGS) -o $(BINDIR)/questionnaire ./cmd/questionnaire

# Binaire CONSULTANT : ajoute le suivi historique SQLite (hors clé).
build-consultant:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=0 $(GO) build -tags history $(BUILDFLAGS) -o $(BINDIR)/orchestrator-consultant ./cmd/orchestrator

clean:
	rm -rf $(BINDIR)
