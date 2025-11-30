package utils

import (
	"bufio"
	"os"
)

func Scanner() string {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	text := scanner.Text()
	return text
}
