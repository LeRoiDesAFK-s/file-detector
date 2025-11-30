package utils

import "fmt"

func FormatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d octets", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"Ko", "Mo", "Go", "To"}
	return fmt.Sprintf("%.2f %s (%d octets)", float64(size)/float64(div), units[exp], size)
}
