package common

import (
	"time"

	utils "github.com/vul-dbgen/share"
)

const CompactCVEDBName = "cvedb.compact"
const RegularCVEDBName = "cvedb.regular"
const CVESourceRoot = "vul-source/"

const RHELCpeMapFile = "rhel-cpe.map"

type NVDMetadata struct {
	Description      string `json:"description,omitempty"`
	Severity         Priority
	CVSSv2           CVSS
	CVSSv3           CVSS
	VulnVersions     []NVDvulnerableVersion
	PublishedDate    time.Time
	LastModifiedDate time.Time
	Link             string
}

type NVDvulnerableVersion struct {
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

type CVSS struct {
	Vectors string
	Score   float64
}

// database format

type DBFile struct {
	Filename string
	Key      KeyVersion
	Files    []utils.TarFileInfo
}

type KeyVersion struct {
	Version    string
	UpdateTime string
	Keys       map[string]string
	Shas       map[string]string
}

type FeaShort struct {
	Name    string `json:"N"`
	Version string `json:"V"`
	MinVer  string `json:"MV"`
}

type VulShort struct {
	Name      string `json:"N"`
	Namespace string `json:"NS"`
	Fixin     []FeaShort
	CPEs      []string `json:"CPE"`
}

type FeaFull struct {
	Name    string `json:"N"`
	Version string `json:"V"`
	MinVer  string `json:"MV"`
	AddedBy string `json:"A"`
}

type VulFull struct {
	Name        string    `json:"N"`
	Namespace   string    `json:"NS"`
	Description string    `json:"D"`
	Link        string    `json:"L"`
	Severity    Priority  `json:"S"`
	CVSSv2      CVSS      `json:"C2"`
	CVSSv3      CVSS      `json:"C3"`
	FixedBy     string    `json:"FB"`
	FixedIn     []FeaFull `json:"FI"`
	CPEs        []string  `json:"CPE,omitempty"`
	CVEs        []string  `json:"CVE,omitempty"`
	FeedRating  string    `json:"RATE,omitempty"`
	IssuedDate  time.Time `json:"Issue"`
	LastModDate time.Time `json:"LastMod"`
}

type AppModuleVersion struct {
	OpCode  string `json:"O"`
	Version string `json:"V"`
}

type AppModuleVul struct {
	VulName       string             `json:"VN"`
	AppName       string             `json:"AN"`
	ModuleName    string             `json:"MN"`
	Description   string             `json:"D"`
	Link          string             `json:"L"`
	Score         float64            `json:"SC"`
	Vectors       string             `json:"VV2"`
	ScoreV3       float64            `json:"SC3"`
	VectorsV3     string             `json:"VV3"`
	Severity      Priority           `json:"SE"`
	AffectedVer   []AppModuleVersion `json:"AV"`
	FixedVer      []AppModuleVersion `json:"FV"`
	UnaffectedVer []AppModuleVersion `json:"UV",omitempty`
	IssuedDate    time.Time          `json:"Issue"`
	LastModDate   time.Time          `json:"LastMod"`
	CVEs          []string           `json:"-"`
}

// ---

type Feature struct {
	Name      string
	Namespace string
}

type FeatureVersion struct {
	Name    string
	Feature Feature
	Version Version
	MinVer  Version
}

type CVE struct {
	Name   string
	CVSSv2 CVSS
	CVSSv3 CVSS
}

type Vulnerability struct {
	Name      string
	Namespace string

	Description string
	Link        string
	Severity    Priority
	CVSSv2      CVSS
	CVSSv3      CVSS
	IssuedDate  time.Time
	LastModDate time.Time
	CVEs        []CVE

	FixedIn    []FeatureVersion
	CPEs       []string
	FeedRating string
}

type RawFile struct {
	Name string
	Raw  []byte
}

// ---

// UbuntuReleasesMapping translates Ubuntu code names to version numbers
var UbuntuReleasesMapping = map[string]string{
	"upstream":         "upstream",
	"precise":          "12.04",
	"precise/esm":      "12.04",
	"quantal":          "12.10",
	"raring":           "13.04",
	"trusty":           "14.04",
	"trusty/esm":       "14.04",
	"utopic":           "14.10",
	"vivid":            "15.04",
	"wily":             "15.10",
	"xenial":           "16.04",
	"esm-infra/xenial": "16.04",
	"yakkety":          "16.10",
	"zesty":            "17.04",
	"artful":           "17.10",
	"bionic":           "18.04",
	"cosmic":           "18.10",
	"disco":            "19.04",
	"eoan":             "19.10",
	"focal":            "20.04",
	"groovy":           "20.10",
	"hirsute":          "21.04",
	"impish":           "21.10",
	"jammy":            "22.04",
	"kinetic":          "22.10",
	"lunar":            "23.04",
	"mantic":           "23.10",
	"noble":            "24.04",
	"esm-apps/bionic":  "18.04",
	"esm-apps/focal":   "20.04",
	"esm-apps/jammy":   "22.04",
	"esm-apps/noble":   "24.04",
}

var DebianReleasesMapping = map[string]string{
	// Code names
	"squeeze":  "6",
	"wheezy":   "7",
	"jessie":   "8",
	"stretch":  "9",
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
	"forky":    "14",
	"sid":      "unstable",

	// Class names
	"oldoldstable": "7",
	"oldstable":    "8",
	"stable":       "9",
	"testing":      "10",
	"unstable":     "unstable",
}
