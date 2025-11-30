package detector

import (
	"file-detector/internal/utils"
	"fmt"
	"os"
	"strings"
	"time"
)

func SaveReport(analyses []FileAnalysis, isDirectory bool) {
	os.MkdirAll("output", 0755)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("output/scan_%s_%s.txt",
		map[bool]string{true: "directory", false: "file"}[isDirectory],
		timestamp)

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("%sErreur rapport: %v%s\n", utils.Red, err, utils.Reset)
		return
	}
	defer file.Close()

	file.WriteString(strings.Repeat("=", 70) + "\n")
	file.WriteString("RAPPORT D'ANALYSE DE FICHIERS\n")
	file.WriteString(strings.Repeat("=", 70) + "\n")
	file.WriteString(fmt.Sprintf("Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	file.WriteString(fmt.Sprintf("Type: %s\n", map[bool]string{true: "Scan de dossier", false: "Scan de fichier"}[isDirectory]))
	file.WriteString(fmt.Sprintf("Nombre total: %d\n", len(analyses)))
	file.WriteString(strings.Repeat("=", 70) + "\n\n")

	suspicious := 0
	unsupported := 0
	detected := 0
	skipped := 0
	typeCount := make(map[string]int)

	for _, analysis := range analyses {
		if analysis.IsSuspicious {
			suspicious++
		}
		if !analysis.IsSupported && !analysis.IsSkipped {
			unsupported++
		}
		if analysis.IsSupported {
			detected++
			if len(analysis.Matches) > 0 {
				typeCount[analysis.Matches[0].Class]++
			}
		}
		if analysis.IsSkipped {
			skipped++
		}
	}

	file.WriteString("STATISTIQUES\n")
	file.WriteString(strings.Repeat("-", 70) + "\n")
	file.WriteString(fmt.Sprintf("Total: %d\n", len(analyses)))
	file.WriteString(fmt.Sprintf("Detectes: %d\n", detected))
	file.WriteString(fmt.Sprintf("Non supportes: %d\n", unsupported))
	file.WriteString(fmt.Sprintf("Ignores: %d\n", skipped))
	file.WriteString(fmt.Sprintf("Suspects: %d\n", suspicious))
	file.WriteString(strings.Repeat("-", 70) + "\n\n")

	if len(typeCount) > 0 {
		file.WriteString("TYPES DETECTES\n")
		file.WriteString(strings.Repeat("-", 70) + "\n")
		for fileType, count := range typeCount {
			file.WriteString(fmt.Sprintf("%s: %d\n", fileType, count))
		}
		file.WriteString("\n")
	}

	if suspicious > 0 {
		file.WriteString("FICHIERS SUSPECTS\n")
		file.WriteString(strings.Repeat("=", 70) + "\n\n")

		for _, analysis := range analyses {
			if analysis.IsSuspicious {
				file.WriteString(fmt.Sprintf("Fichier: %s\n", analysis.Path))
				file.WriteString(fmt.Sprintf("Taille: %s\n", utils.FormatSize(analysis.Size)))
				file.WriteString(fmt.Sprintf("Type: %s\n", analysis.DetectedType))
				file.WriteString(fmt.Sprintf("Extension actuelle: .%s\n", analysis.ActualExt))
				if len(analysis.DetectedExt) > 0 {
					file.WriteString(fmt.Sprintf("Extension attendue: %s\n", strings.Join(analysis.DetectedExt, ", ")))
				}
				file.WriteString(fmt.Sprintf("Raison: %s\n", analysis.SuspiciousReason))
				file.WriteString(strings.Repeat("-", 70) + "\n\n")
			}
		}
	}

	if unsupported > 0 {
		file.WriteString("FICHIERS NON SUPPORTES\n")
		file.WriteString(strings.Repeat("=", 70) + "\n\n")

		for _, analysis := range analyses {
			if !analysis.IsSupported && !analysis.IsSkipped {
				file.WriteString(fmt.Sprintf("Fichier: %s\n", analysis.Path))
				file.WriteString(fmt.Sprintf("Taille: %s\n", utils.FormatSize(analysis.Size)))
				file.WriteString(fmt.Sprintf("Extension: .%s\n", analysis.ActualExt))
				file.WriteString(fmt.Sprintf("Raison: %s\n", analysis.SuspiciousReason))
				file.WriteString(strings.Repeat("-", 70) + "\n\n")
			}
		}
	}

	file.WriteString("DETAILS COMPLETS\n")
	file.WriteString(strings.Repeat("=", 70) + "\n\n")

	for i, analysis := range analyses {
		file.WriteString(fmt.Sprintf("[%d/%d] %s\n", i+1, len(analyses), analysis.Name))
		file.WriteString(fmt.Sprintf("Chemin: %s\n", analysis.Path))
		file.WriteString(fmt.Sprintf("Taille: %s\n", utils.FormatSize(analysis.Size)))

		if analysis.ActualExt != "" {
			file.WriteString(fmt.Sprintf("Extension: .%s\n", analysis.ActualExt))
		}

		if analysis.IsSkipped {
			file.WriteString(fmt.Sprintf("Statut: Ignore - %s\n", analysis.SkipReason))
		} else if !analysis.IsSupported {
			file.WriteString(fmt.Sprintf("Statut: Non supporte - %s\n", analysis.SuspiciousReason))
		} else {
			file.WriteString(fmt.Sprintf("Type: %s\n", analysis.DetectedType))
			if len(analysis.DetectedExt) > 0 {
				file.WriteString(fmt.Sprintf("Extension attendue: %s\n", strings.Join(analysis.DetectedExt, ", ")))
			}
			if len(analysis.Matches) > 0 {
				file.WriteString(fmt.Sprintf("Classe: %s\n", analysis.Matches[0].Class))
			}
			if len(analysis.Matches) > 1 {
				file.WriteString(fmt.Sprintf("Signatures: %d correspondances\n", len(analysis.Matches)))
			}
			if analysis.IsSuspicious {
				file.WriteString(fmt.Sprintf("Alerte: %s\n", analysis.SuspiciousReason))
			}
		}

		file.WriteString(strings.Repeat("-", 70) + "\n\n")
	}

	file.WriteString(strings.Repeat("=", 70) + "\n")
	file.WriteString("FIN DU RAPPORT\n")
	file.WriteString(strings.Repeat("=", 70) + "\n")

	fmt.Printf("%sRapport: %s%s\n", utils.Green, filename, utils.Reset)
}

func DisplayAnalysis(analysis FileAnalysis, buffer []byte) {
	if analysis.IsSkipped {
		DisplaySkippedFile(analysis)
		return
	}

	DisplayFileHeader(analysis.Path, analysis.Name, analysis.Size, analysis.ActualExt)

	if len(buffer) > 0 {
		DisplayMagicBytes(buffer)
	}

	DisplayDetectionResults(analysis)

	fmt.Println(strings.Repeat("=", 70))
}
