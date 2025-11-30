package detector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"file-detector/internal/utils"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var signatures []FileSignature

func LoadSignatures(jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("erreur de lecture du fichier de signatures: %w", err)
	}

	if err := json.Unmarshal(data, &signatures); err != nil {
		return fmt.Errorf("erreur de parsing JSON: %w", err)
	}

	fmt.Printf("%s%d signatures chargees%s\n\n", utils.Green, len(signatures), utils.Reset)
	return nil
}

func GetSignatures() []FileSignature {
	return signatures
}

func FindMatches(buffer []byte) []FileSignature {
	var matches []FileSignature

	for _, sig := range signatures {
		if matchSignature(buffer, sig) {
			matches = append(matches, sig)
		}
	}

	return matches
}

func matchSignature(data []byte, sig FileSignature) bool {
	header := strings.ReplaceAll(sig.Header, " ", "")
	header = strings.ReplaceAll(header, "?", "0")

	headerBytes, err := hex.DecodeString(header)
	if err != nil {
		return false
	}

	offset := 0
	if sig.HeaderOffset != "" && sig.HeaderOffset != "0" {
		offset, err = strconv.Atoi(sig.HeaderOffset)
		if err != nil {
			return false
		}
	}

	if offset+len(headerBytes) > len(data) {
		return false
	}

	return bytes.Equal(data[offset:offset+len(headerBytes)], headerBytes)
}
