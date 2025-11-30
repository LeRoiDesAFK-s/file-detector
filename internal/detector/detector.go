package detector

import (
	"file-detector/internal/utils"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ScanFile() bool {
	fmt.Print(utils.Yellow + "Entrez le chemin vers le fichier : " + utils.Reset)
	path := utils.Scanner()

	if !IsValidPath(path) {
		fmt.Println(utils.Red, "Erreur : Chemin invalide", utils.Reset)
		return false
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		fmt.Println(utils.Red, "Erreur : Fichier introuvable", utils.Reset)
		return false
	}

	fmt.Println(utils.Green, "Fichier trouve:", path, utils.Reset)
	fmt.Println()

	analysis := AnalyzeFile(path)
	SaveReport([]FileAnalysis{analysis}, false)

	return true
}

func ScanDirectory() bool {
	fmt.Print(utils.Yellow + "Entrez le chemin vers le dossier : " + utils.Reset)
	path := utils.Scanner()

	if !IsValidPath(path) {
		fmt.Println(utils.Red, "Erreur : Chemin invalide", utils.Reset)
		return false
	}

	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		fmt.Println(utils.Red, "Erreur : Dossier introuvable", utils.Reset)
		return false
	}

	fmt.Println(utils.Green, "Dossier trouve:", path, utils.Reset)
	fmt.Println()

	fmt.Print(utils.Cyan + "Scanner les sous-dossiers ? (o/N) : " + utils.Reset)
	recursive := strings.ToLower(utils.Scanner())
	isRecursive := recursive == "o" || recursive == "oui" || recursive == "y" || recursive == "yes"

	ExecuteDirectory(path, isRecursive)
	return true
}

func ExecuteDirectory(dirPath string, recursive bool) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%sAnalyse du dossier%s\n", utils.Cyan, utils.Reset)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Chemin: %s\n", dirPath)
	fmt.Printf("Mode: %s\n", map[bool]string{true: "Recursif", false: "Non recursif"}[recursive])
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	var files []string
	var err error

	if recursive {
		files, err = getFilesRecursive(dirPath)
	} else {
		files, err = getFilesNonRecursive(dirPath)
	}

	if err != nil {
		fmt.Printf("%sErreur: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	if len(files) == 0 {
		fmt.Printf("%sAucun fichier a analyser%s\n", utils.Yellow, utils.Reset)
		return
	}

	fmt.Printf("%sAnalyse de %d fichier(s)...%s\n\n", utils.Cyan, len(files), utils.Reset)

	stats := &ScanStats{
		Total:       len(files),
		TypeCount:   make(map[string]int),
		SkipReasons: make(map[string]int),
		Analyses:    make([]FileAnalysis, 0),
	}

	for i, filePath := range files {
		fmt.Printf("%s[%d/%d]%s %s\n", utils.Purple, i+1, len(files), utils.Reset, filePath)
		analysis := analyzeFileQuick(filePath, stats)
		stats.Analyses = append(stats.Analyses, analysis)

		if !analysis.IsSkipped {
			fmt.Println()
		}
	}

	DisplayScanSummary(stats)
	SaveReport(stats.Analyses, true)
}

func getFilesNonRecursive(dirPath string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			fullPath := filepath.Join(dirPath, entry.Name())
			ext := strings.TrimPrefix(filepath.Ext(entry.Name()), ".")

			if skip, _ := shouldSkipFile(entry.Name(), ext); !skip {
				data, err := os.ReadFile(fullPath)
				if err == nil && !isTextFile(data) {
					files = append(files, fullPath)
				}
			}
		}
	}
	return files, nil
}

func getFilesRecursive(dirPath string) ([]string, error) {
	var files []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if skip, _ := shouldSkipPath(path); skip {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.TrimPrefix(filepath.Ext(info.Name()), ".")
		if skip, _ := shouldSkipFile(info.Name(), ext); !skip {
			data, err := os.ReadFile(path)
			if err == nil && !isTextFile(data) {
				files = append(files, path)
			}
		}

		return nil
	})
	return files, err
}

func analyzeFileQuick(path string, stats *ScanStats) FileAnalysis {
	analysis := FileAnalysis{
		Path: path,
		Name: filepath.Base(path),
	}

	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("  %sErreur: %v%s\n", utils.Red, err, utils.Reset)
		stats.Errors++
		return analysis
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Printf("  %sErreur: %v%s\n", utils.Red, err, utils.Reset)
		stats.Errors++
		return analysis
	}

	analysis.Size = fileInfo.Size()
	ext := strings.TrimPrefix(filepath.Ext(path), ".")
	analysis.ActualExt = ext

	bufferSize := 2048
	if fileInfo.Size() < int64(bufferSize) {
		bufferSize = int(fileInfo.Size())
	}

	buffer := make([]byte, bufferSize)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		fmt.Printf("  %sErreur: %v%s\n", utils.Red, err, utils.Reset)
		stats.Errors++
		return analysis
	}
	buffer = buffer[:n]

	matches := FindMatches(buffer)

	if len(matches) == 0 {
		analysis.IsSupported = false
		analysis.SuspiciousReason = fmt.Sprintf("Format .%s non reconnu", ext)
		stats.Unsupported++
		fmt.Printf("  %s[NON SUPPORTE]%s Format .%s non reconnu\n",
			utils.Red, utils.Reset, ext)
		return analysis
	}

	analysis.IsSupported = true
	match := matches[0]
	analysis.DetectedType = match.Description
	analysis.Matches = matches

	if match.Extension != "" && match.Extension != "null" {
		analysis.DetectedExt = strings.Split(match.Extension, "|")
	}

	if len(analysis.DetectedExt) > 0 && analysis.ActualExt != "" {
		extensionMatch := false
		for _, validExt := range analysis.DetectedExt {
			if strings.EqualFold(validExt, analysis.ActualExt) {
				extensionMatch = true
				break
			}
		}

		if !extensionMatch {
			isCriticalClass := criticalClasses[match.Class]
			isDangerousExt := dangerousExtensions[strings.ToLower(analysis.ActualExt)]

			if isCriticalClass && isDangerousExt {
				analysis.IsSuspicious = true
				analysis.SuspiciousReason = fmt.Sprintf(
					"Extension executable .%s ne correspond pas au type %s (attendu: %s)",
					analysis.ActualExt, match.Description, strings.Join(analysis.DetectedExt, ", "))
				stats.Suspicious++
			} else if isCriticalClass {
				analysis.IsSuspicious = true
				analysis.SuspiciousReason = fmt.Sprintf(
					"Extension .%s ne correspond pas au type %s (attendu: %s)",
					analysis.ActualExt, match.Description, strings.Join(analysis.DetectedExt, ", "))
				stats.Suspicious++
			}
		}
	}

	fmt.Printf("  %sTaille:%s %s\n", utils.Yellow, utils.Reset, utils.FormatSize(analysis.Size))
	fmt.Printf("  %sType:%s %s\n", utils.Green, utils.Reset, match.Description)

	if len(analysis.DetectedExt) > 0 {
		fmt.Printf("  %sExtension attendue:%s %s\n", utils.Cyan, utils.Reset,
			strings.Join(analysis.DetectedExt, ", "))
	}

	fmt.Printf("  %sExtension actuelle:%s .%s\n", utils.Cyan, utils.Reset, analysis.ActualExt)
	fmt.Printf("  %sClasse:%s %s\n", utils.Cyan, utils.Reset, match.Class)

	if len(matches) > 1 {
		fmt.Printf("  %s(%d signatures)%s\n", utils.Yellow, len(matches), utils.Reset)
	}

	if analysis.IsSuspicious {
		fmt.Printf("  %s[SUSPECT]%s %s\n", utils.Red, utils.Reset, analysis.SuspiciousReason)
	}

	stats.Detected++
	stats.TypeCount[match.Class]++

	return analysis
}

func IsValidPath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
