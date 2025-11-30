package main

import (
	"file-detector/internal/detector"
	"file-detector/internal/utils"
	"fmt"
	"os"
)

func init() {
	if err := detector.LoadSignatures("internal/detector/file_signatures.json"); err != nil {
		fmt.Printf("%sErreur fatale: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Println("Assurez-vous que le fichier 'internal/detector/file_signatures.json' existe.")
		os.Exit(1)
	}
}

func Menu() {
	utils.ClearTerminal()
	art := `_____ _ _                _      _            _             
|  ___(_) | ___        __| | ___| |_ ___  ___| |_ ___  _ __ 
| |_  | | |/ _ \_____ / _` + "`" + ` |/ _ \ __/ _ \/ __| __/ _ \| '__|
|  _| | | |  __/_____| (_| |  __/ ||  __/ (__| || (_) | |   
|_|   |_|_|\___|      \__,_|\___|\__\___|\___|\__\___/|_|   `

	fmt.Println(utils.Blue, art, utils.Reset, "\n")
	fmt.Println("[1] ► Scanner un fichier\n\tUtilisation : /path/to/file.extension")
	fmt.Println("[2] ► Scanner un dossier\n\tUtilisation : /path/to/folder")
	fmt.Println("[0] ► Quitter")

	ChoseCase()
}

func ChoseCase() {
	attempt := 0
	maxAttempts := 3

	for {
		fmt.Print(utils.Cyan, "Entrez un nombre pour sélectionner une option : ", utils.Reset)
		number := utils.Scanner()

		switch number {
		case "0":
			fmt.Println(utils.Purple, "Sortie du programme", utils.Reset)
			return

		case "1":
			if detector.ScanFile() {
				fmt.Println(utils.Green, "\nAnalyse terminée.", utils.Purple, "Retour au menu.", utils.Reset)
			} else {
				fmt.Println(utils.Red, "\nÉchec de l'analyse.", utils.Purple, "Retour au menu.", utils.Reset)
			}
			utils.WaitConfirm()
			Menu()
			return

		case "2":
			if detector.ScanDirectory() {
				fmt.Println(utils.Green, "\nScan du dossier terminé.", utils.Purple, "Retour au menu.", utils.Reset)
			} else {
				fmt.Println(utils.Red, "\nÉchec du scan.", utils.Purple, "Retour au menu.", utils.Reset)
			}
			utils.WaitConfirm()
			Menu()
			return

		default:
			fmt.Println(utils.Red, "Erreur : Entrée invalide. Veuillez entrer un nombre (0, 1 ou 2).", utils.Reset)
			attempt++

			if attempt >= maxAttempts {
				fmt.Println(utils.Red, "\nTrop de tentatives. ", utils.Purple, "Retour au menu.", utils.Reset)
				utils.WaitConfirm()
				Menu()
				return
			}
		}
	}
}

func main() {
	Menu()
}
