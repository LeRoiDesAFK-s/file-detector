.PHONY: build run clean test

# Variables
BINARY_NAME=file-detector
MAIN_PATH=./cmd/detector

# Compilation
build:
	@echo "Compilation..."
	@go build -o $(BINARY_NAME) $(MAIN_PATH)
	@echo "✓ Binaire créé : $(BINARY_NAME)"

# Exécution
run: build
	@echo "Lancement..."
	@./$(BINARY_NAME)

# Nettoyage
clean:
	@echo "Nettoyage..."
	@rm -f $(BINARY_NAME)
	@go clean
	@echo "✓ Nettoyage terminé"

# Tests
test:
	@echo "Exécution des tests..."
	@go test ./...

# Installation des dépendances
deps:
	@echo "Installation des dépendances..."
	@go mod download
	@go mod tidy

# Tout rebuild
all: clean build
