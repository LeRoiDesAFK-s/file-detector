package detector

import (
	"path/filepath"
	"strings"
)

var textExtensions = map[string]string{
	"txt": "Fichier texte", "md": "Markdown", "py": "Python",
	"js": "JavaScript", "go": "Go", "c": "C", "cpp": "C++",
	"java": "Java", "rs": "Rust", "sh": "Shell", "json": "JSON",
	"xml": "XML", "yaml": "YAML", "yml": "YAML", "toml": "TOML",
	"ini": "INI", "conf": "Config", "log": "Log", "csv": "CSV",
	"html": "HTML", "css": "CSS", "php": "PHP", "rb": "Ruby",
}

var javaArchives = map[string]bool{
	"jar": true, "war": true, "ear": true, "apk": true,
}

var ignoredDirs = []string{
	"node_modules", ".git", ".vscode", "__pycache__",
	"venv", "env", "build", "dist", "target",
}

var dangerousExtensions = map[string]bool{
	"exe": true, "dll": true, "sys": true, "bat": true,
	"cmd": true, "com": true, "scr": true, "vbs": true,
	"js": true, "wsf": true, "msi": true, "jar": true,
	"app": true, "deb": true, "rpm": true, "dmg": true,
	"pkg": true, "run": true, "bin": true, "elf": true,
	"so": true, "dylib": true, "apk": true, "ipa": true,
}

var criticalClasses = map[string]bool{
	"Executable":    true,
	"Compressed":    true,
	"Database":      true,
	"System":        true,
	"Binary":        true,
	"Library":       true,
	"Driver":        true,
	"Application":   true,
	"Installer":     true,
	"Archive":       true,
	"Cryptographic": true,
	"Obfuscated":    true,
}

func shouldSkipFile(filename, ext string) (bool, string) {
	ext = strings.ToLower(ext)

	if javaArchives[ext] {
		return false, ""
	}

	if reason, exists := textExtensions[ext]; exists {
		return true, reason
	}

	if strings.HasPrefix(filename, ".") {
		return true, "Fichier cache"
	}

	return false, ""
}

func shouldSkipPath(path string) (bool, string) {
	pathParts := strings.Split(filepath.ToSlash(strings.ToLower(path)), "/")

	for _, part := range pathParts {
		for _, ignored := range ignoredDirs {
			if part == strings.ToLower(ignored) {
				return true, "Dossier systeme ignore: " + ignored
			}
		}
	}
	return false, ""
}

func isTextFile(data []byte) bool {
	if len(data) == 0 {
		return true
	}

	checkSize := 512
	if len(data) < checkSize {
		checkSize = len(data)
	}

	textBytes := 0
	for i := 0; i < checkSize; i++ {
		b := data[i]
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			textBytes++
		} else if b == 0 {
			return false
		}
	}

	ratio := float64(textBytes) / float64(checkSize)
	return ratio > 0.95
}

func IsJavaArchive(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04
}

func IsCriticalClass(class string) bool {
	return criticalClasses[class]
}

func IsDangerousExtension(ext string) bool {
	return dangerousExtensions[strings.ToLower(ext)]
}

func IsTextExtension(ext string) bool {
	_, exists := textExtensions[strings.ToLower(ext)]
	return exists
}
