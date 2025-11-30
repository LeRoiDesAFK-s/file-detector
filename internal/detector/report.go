package detector

import (
	"encoding/hex"
	"file-detector/internal/utils"
	"fmt"
	"strings"
)

func DisplayFileHeader(path, name string, size int64, actualExt string) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%sAnalyse du fichier%s\n", utils.Cyan, utils.Reset)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%sChemin:%s %s\n", utils.Yellow, utils.Reset, path)
	fmt.Printf("%sNom:%s %s\n", utils.Yellow, utils.Reset, name)
	fmt.Printf("%sTaille:%s %s\n", utils.Yellow, utils.Reset, utils.FormatSize(size))
	if actualExt != "" {
		fmt.Printf("%sExtension:%s .%s\n", utils.Yellow, utils.Reset, actualExt)
	}
	fmt.Println()
}

func DisplayMagicBytes(buffer []byte) {
	fmt.Printf("%sMagic Bytes:%s\n", utils.Cyan, utils.Reset)
	displayHex := 16
	if len(buffer) < displayHex {
		displayHex = len(buffer)
	}
	fmt.Printf("  HEX:   %s\n", hex.EncodeToString(buffer[:displayHex]))
	fmt.Printf("  ASCII: %s\n", formatASCII(buffer[:displayHex]))
	fmt.Println()
}

func DisplayDetectionResults(analysis FileAnalysis) {
	fmt.Printf("%sResultats:%s\n", utils.Cyan, utils.Reset)

	if !analysis.IsSupported {
		fmt.Printf("  %s[NON SUPPORTE]%s %s\n", utils.Red, utils.Reset, analysis.SuspiciousReason)
		fmt.Println("  Verifiez le fichier ou ajoutez la signature manquante")
		return
	}

	fmt.Printf("  %sType:%s %s\n", utils.Green, utils.Reset, analysis.DetectedType)

	if len(analysis.DetectedExt) > 0 {
		fmt.Printf("  %sExtension attendue:%s %s\n", utils.Cyan, utils.Reset,
			strings.Join(analysis.DetectedExt, ", "))
	}

	fmt.Printf("  %sExtension actuelle:%s .%s\n", utils.Cyan, utils.Reset, analysis.ActualExt)

	if len(analysis.Matches) > 0 {
		fmt.Printf("  %sClasse:%s %s\n", utils.Cyan, utils.Reset, analysis.Matches[0].Class)
	}

	if len(analysis.Matches) > 1 {
		fmt.Printf("  %s(%d signatures correspondent)%s\n",
			utils.Yellow, len(analysis.Matches), utils.Reset)
	}

	if analysis.IsSuspicious {
		fmt.Printf("  %s[SUSPECT]%s %s\n", utils.Red, utils.Reset, analysis.SuspiciousReason)
	}
}

func DisplaySkippedFile(analysis FileAnalysis) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%sAnalyse du fichier%s\n", utils.Cyan, utils.Reset)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%sChemin:%s %s\n", utils.Yellow, utils.Reset, analysis.Path)
	fmt.Printf("%sNom:%s %s\n", utils.Yellow, utils.Reset, analysis.Name)
	fmt.Printf("%sTaille:%s %s\n", utils.Yellow, utils.Reset, utils.FormatSize(analysis.Size))
	fmt.Printf("\n%s[IGNORE]%s %s\n", utils.Yellow, utils.Reset, analysis.SkipReason)
	fmt.Println(strings.Repeat("=", 70))
}

func DisplayScanSummary(stats *ScanStats) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%sResume%s\n", utils.Cyan, utils.Reset)
	fmt.Println(strings.Repeat("=", 70))

	analyzed := stats.Total - stats.Skipped - stats.Errors

	fmt.Printf("Fichiers analyses: %d\n", analyzed)
	fmt.Printf("Fichiers ignores: %d\n", stats.Skipped)

	if analyzed > 0 {
		fmt.Printf("Detectes: %d (%.1f%%)\n", stats.Detected,
			float64(stats.Detected)/float64(analyzed)*100)
		fmt.Printf("Non detectes: %d (%.1f%%)\n", stats.Undetected,
			float64(stats.Undetected)/float64(analyzed)*100)
	}

	if stats.Unsupported > 0 {
		fmt.Printf("\n%sFichiers non supportes: %d%s\n",
			utils.Yellow, stats.Unsupported, utils.Reset)
	}

	if stats.Suspicious > 0 {
		fmt.Printf("\n%s[ALERTE] %d fichier(s) suspect(s)%s\n",
			utils.Red, stats.Suspicious, utils.Reset)

		for _, analysis := range stats.Analyses {
			if analysis.IsSuspicious {
				fmt.Printf("\n  %s\n", analysis.Path)
				fmt.Printf("    Type: %s\n", analysis.DetectedType)
				fmt.Printf("    Extension: %s (actuelle: %s)\n",
					strings.Join(analysis.DetectedExt, ", "), analysis.ActualExt)
				fmt.Printf("    Raison: %s\n", analysis.SuspiciousReason)
			}
		}
	} else {
		fmt.Printf("\n%sAucun fichier suspect%s\n", utils.Green, utils.Reset)
	}

	if len(stats.TypeCount) > 0 {
		fmt.Printf("\n%sTypes detectes:%s\n", utils.Cyan, utils.Reset)
		for fileType, count := range stats.TypeCount {
			fmt.Printf("  %s: %d\n", fileType, count)
		}
	}

	fmt.Println(strings.Repeat("=", 70))
}

func formatASCII(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result.WriteByte(b)
		} else {
			result.WriteByte('.')
		}
	}
	return result.String()
}
