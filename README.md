# File-Detector

**Analyseur de types de fichiers basé sur les signatures binaires (Magic Numbers)**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)](https://github.com)

---

## Description

**File-Detector** est un outil en ligne de commande développé en Go permettant d'identifier la véritable nature d'un fichier en analysant sa signature binaire (Magic Numbers), indépendamment de son extension déclarée.

Ce projet répond à une problématique de sécurité courante : la possibilité de dissimuler la nature réelle d'un fichier en modifiant son extension. Par exemple, un exécutable Windows (.exe) peut être renommé en image (.png) pour tromper l'utilisateur ou contourner des filtres de sécurité.

---

## Architecture du projet

### Structure modulaire

```
file-detector/
├── cmd/detector/main.go           # Point d'entrée de l'application
├── internal/detector/
│   ├── analyzer.go                # Logique d'analyse des fichiers
│   ├── filters.go                 # Filtrage (fichiers texte, dossiers système)
│   ├── signatures.go              # Chargement et matching des signatures
│   ├── display.go                 # Affichage formaté dans le terminal
│   ├── report.go                  # Génération de rapports texte
│   ├── stats.go                   # Calcul des statistiques d'analyse
│   ├── types.go                   # Structures de données
│   └── file_signatures.json       # Base de données (500+ signatures)
├── internal/utils/
│   ├── color.go                   # Gestion des couleurs terminal
│   ├── scanner.go                 # Gestion de la saisie utilisateur
│   └── clearTerminal.go           # Nettoyage de l'écran
├── output/                        # Rapports générés automatiquement
├── Makefile                       # Commandes de compilation
└── README.md
```

---

## Installation

### Prérequis

- **Go 1.21 ou supérieur** ([télécharger Go](https://go.dev/dl/))
- **Git** pour cloner le dépôt

### Compilation

```bash
# Cloner le dépôt
git clone https://github.com/votre-username/file-detector.git
cd file-detector

# Compiler le projet
make build

# Lancer l'application
make run
```
---

## Licence

Ce projet est sous licence **MIT**. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.

---

## Contributions

Les contributions sont les bienvenues ! Pour contribuer :

1. Fork le projet
2. Créez une branche (`git checkout -b feature/amelioration`)
3. Committez vos changements (`git commit -m 'Ajout d'une fonctionnalité'`)
4. Push vers la branche (`git push origin feature/amelioration`)
5. Ouvrez une Pull Request

---

## Auteur

Développé dans le cadre d'un projet d'apprentissage sur l'analyse binaire et la sécurité informatique.