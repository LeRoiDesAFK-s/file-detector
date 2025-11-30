package utils

import "fmt"

func WaitConfirm(message ...string) {
	msg := "Appuyez sur Entrée pour continuer..."
	if len(message) > 0 {
		msg = message[0]
	}
	fmt.Print(Cyan, msg, Reset)
	Scanner()
}
