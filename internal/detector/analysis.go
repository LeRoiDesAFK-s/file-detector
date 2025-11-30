package detector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func AnalyzeFile(filePath string) FileAnalysis {
	analysis := FileAnalysis{
		Path:        filePath,
		Name:        filepath.Base(filePath),
		ActualExt:   strings.ToLower(strings.TrimPrefix(filepath.Ext(filePath), ".")),
		IsSupported: false,
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		analysis.IsSkipped = true
		analysis.SkipReason = fmt.Sprintf("Erreur d'acces: %v", err)
		return analysis
	}

	analysis.Size = fileInfo.Size()

	if skip, reason := shouldSkipFile(analysis.Name, analysis.ActualExt); skip {
		analysis.IsSkipped = true
		analysis.SkipReason = reason
		return analysis
	}

	file, err := os.Open(filePath)
	if err != nil {
		analysis.IsSkipped = true
		analysis.SkipReason = fmt.Sprintf("Impossible d'ouvrir: %v", err)
		return analysis
	}
	defer file.Close()

	buffer := make([]byte, 2048)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		analysis.IsSkipped = true
		analysis.SkipReason = fmt.Sprintf("Erreur de lecture: %v", err)
		return analysis
	}
	buffer = buffer[:n]

	if !javaArchives[analysis.ActualExt] && isTextFile(buffer) {
		analysis.IsSkipped = true
		analysis.SkipReason = "Fichier texte detecte"
		analysis.IsText = true
		return analysis
	}

	matches := FindMatches(buffer)

	if len(matches) == 0 {
		analysis.IsSupported = false
		analysis.DetectedType = "Format non supporte"
		analysis.SuspiciousReason = fmt.Sprintf(
			"Le fichier .%s n'est pas dans la base de signatures",
			analysis.ActualExt,
		)
		return analysis
	}

	analysis.IsSupported = true
	bestMatch := matches[0]
	analysis.DetectedType = bestMatch.Description
	analysis.DetectedExt = parseExtensions(bestMatch.Extension)
	analysis.Matches = matches

	if analysis.ActualExt != "" && len(analysis.DetectedExt) > 0 {
		extensionMatch := false
		for _, ext := range analysis.DetectedExt {
			if strings.EqualFold(ext, analysis.ActualExt) {
				extensionMatch = true
				break
			}
		}

		if !extensionMatch {
			isCritical := IsCriticalClass(bestMatch.Class)
			isDangerous := IsDangerousExtension(analysis.ActualExt)

			if isDangerous || isCritical {
				analysis.IsSuspicious = true
				analysis.SuspiciousReason = fmt.Sprintf(
					"Extension .%s ne correspond pas au type %s (attendu: %s)",
					analysis.ActualExt,
					analysis.DetectedType,
					strings.Join(analysis.DetectedExt, ", "),
				)
			}
		}
	}

	return analysis
}

func parseExtensions(extStr string) []string {
	parts := strings.Split(extStr, ",")
	var exts []string
	for _, part := range parts {
		ext := strings.TrimSpace(part)
		if ext != "" && ext != "null" {
			exts = append(exts, ext)
		}
	}
	return exts
}
