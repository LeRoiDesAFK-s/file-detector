package detector

type FileSignature struct {
	Description  string `json:"ASCII File Description"`
	Header       string `json:"Header (HEX)"`
	Extension    string `json:"File Extension"`
	Class        string `json:"File Class"`
	HeaderOffset string `json:"Header Offset"`
	Trailer      string `json:"Trailer (HEX)"`
}

type FileAnalysis struct {
	Path             string
	Name             string
	Size             int64
	DetectedType     string
	DetectedExt      []string
	ActualExt        string
	IsSuspicious     bool
	SuspiciousReason string
	IsSupported      bool
	Matches          []FileSignature
	IsSkipped        bool
	SkipReason       string
	IsText           bool
}

type ScanStats struct {
	Total       int
	Detected    int
	Undetected  int
	Suspicious  int
	Skipped     int
	Unsupported int
	Errors      int
	TypeCount   map[string]int
	SkipReasons map[string]int
	Analyses    []FileAnalysis
}
