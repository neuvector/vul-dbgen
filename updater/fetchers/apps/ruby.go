package apps

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"unicode"

	log "github.com/sirupsen/logrus"
	yamlv2 "gopkg.in/yaml.v2"

	"github.com/vul-dbgen/common"
)

const rubyGitUrl = "https://github.com/rubysec/ruby-advisory-db"

func rubyUpdate() error {
	log.Debug("")

	repositoryLocalPath, err := ioutil.TempDir(os.TempDir(), "ruby-advisory-db")
	if err != nil {
		return fmt.Errorf("something went wrong when interacting with the fs")
	}
	defer os.RemoveAll(repositoryLocalPath)

	cmd := exec.Command("git", "clone", rubyGitUrl, ".")
	cmd.Dir = repositoryLocalPath
	if out, err := cmd.CombinedOutput(); err != nil {
		log.WithError(err).WithField("output", string(out)).Error("could not pull ruby-advisory-db repository")
		return fmt.Errorf("could not download requested resource")
	}

	baseDir := repositoryLocalPath + "/gems"
	d, err := os.Open(baseDir)
	if err != nil {
		return err
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		return err
	}
	allPackages := make([]*common.AppModuleVul, 0)
	for _, file := range files {
		if file.IsDir() {
			mvs := getYaml(baseDir + "/" + file.Name())
			allPackages = append(allPackages, mvs...)
		}
	}
	for _, pkg := range allPackages {
		if pkg == nil {
			continue
		}

		pkg.CVEs = []string{pkg.VulName}
		addAppVulMap(pkg)
		vulCache.Add(pkg.VulName)
	}

	return nil
}

func getYaml(dir string) []*common.AppModuleVul {
	all := make([]*common.AppModuleVul, 0)
	d, err := os.Open(dir)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Get year yaml fail")
		return all
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		return all
	}

	for _, file := range files {
		name := file.Name()
		if !file.IsDir() && strings.HasSuffix(name, ".yml") {
			jv := parseRubyYml(dir + "/" + name)
			if jv.cve != "" && jv != nil {
				mv := rubyVulToModule(jv)
				all = append(all, mv)
			}
		}
	}
	return all
}

type rubyVul struct {
	gem                 string
	cve                 string
	osvdb               string
	url                 string
	title               string
	date                string
	description         string
	cvssV2              float64
	cvssV3              float64
	patched_versions    []string
	unaffected_versions []string
}

func parseRubyYml(yaml string) *rubyVul {
	m := make(map[interface{}]interface{})
	data, _ := ioutil.ReadFile(yaml)
	err := yamlv2.Unmarshal([]byte(data), &m)
	if err != nil {
		return nil
	}
	var j rubyVul
	if v, ok := m["gem"]; ok {
		if str, ok := v.(string); ok {
			j.gem = str
		}
	}
	if v, ok := m["cve"]; ok {
		if str, ok := v.(string); ok {
			j.cve = "CVE-" + str
		}
	}
	if v, ok := m["title"]; ok {
		if str, ok := v.(string); ok {
			j.title = str
		}
	}
	if v, ok := m["cvss_v2"]; ok {
		if f, ok := v.(float64); ok {
			j.cvssV2 = f
		}
	}
	if v, ok := m["cvss_v3"]; ok {
		if f, ok := v.(float64); ok {
			j.cvssV3 = f
		}
	}
	if v, ok := m["description"]; ok {
		if str, ok := v.(string); ok {
			j.description = str
		}
	}
	if v, ok := m["url"]; ok {
		if str, ok := v.(string); ok {
			j.url = str
		}
	}
	if ma, ok := m["patched_versions"]; ok {
		if afs, ok := ma.([]interface{}); ok {
			for _, v := range afs {
				j.patched_versions = append(j.patched_versions, v.(string))
			}
		}
	}
	if ma, ok := m["unaffected_versions"]; ok {
		if afs, ok := ma.([]interface{}); ok {
			for _, v := range afs {
				j.unaffected_versions = append(j.unaffected_versions, v.(string))
			}
		}
	}

	// if j.cve == "CVE-2018-3760" {
	// 	fmt.Printf("============ meta %+v\n", m)
	// }

	return &j
}

func rubyVulToModule(jv *rubyVul) *common.AppModuleVul {
	mv := &common.AppModuleVul{
		AppName:     "ruby",
		ModuleName:  "ruby:" + jv.gem,
		VulName:     jv.cve,
		Description: jv.title + "/n" + jv.description,
		Score:       jv.cvssV2,
		ScoreV3:     jv.cvssV3,
		Link:        jv.url,
	}
	sort.Slice(jv.patched_versions, func(i, j int) bool {
		str1 := strings.TrimLeftFunc(jv.patched_versions[i], func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})
		str2 := strings.TrimLeftFunc(jv.patched_versions[j], func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})
		return str1 < str2
	})
	sort.Slice(jv.unaffected_versions, func(i, j int) bool {
		str1 := strings.TrimLeftFunc(jv.unaffected_versions[i], func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})
		str2 := strings.TrimLeftFunc(jv.unaffected_versions[j], func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})
		return str1 < str2
	})
	for k, fx := range jv.patched_versions {
		if mver, ok := parseRubyVersion(k, fx, false); ok {
			mv.FixedVer = append(mv.FixedVer, mver...)
		}
	}
	for k, fx := range jv.unaffected_versions {
		if mver, ok := parseRubyVersion(k, fx, false); ok {
			mv.UnaffectedVer = append(mv.UnaffectedVer, mver...)
			if len(mv.FixedVer) > 0 && len(mver) > 0 {
				mver[0].OpCode = "or" + mver[0].OpCode
			}
		}
	}
	if len(jv.patched_versions) == 0 && len(jv.unaffected_versions) == 0 {
		return nil
	}

	// The logic to convert from patched version to affected version is not correct.
	// In scanning, ruby affected version is ignored.
	mv.AffectedVer = generateAffectedVer(jv.patched_versions)

	/*
		if jv.cve == "CVE-2018-3760" {
			for _, pv := range jv.patched_versions {
				fmt.Printf("============ jv.patched %+v\n", pv)
			}
			fmt.Printf("============ mv.FixedVer  %+v\n", mv.FixedVer)
			fmt.Printf("============ mv.unaffectedVer  %+v\n", mv.UnaffectedVer)
			fmt.Printf("============ mv.affectedVer  %+v\n", mv.AffectedVer)
		}
	*/

	return mv
}

func getOperation(op string, rev bool) string {
	if op == ">=" {
		if !rev {
			return "gteq"
		} else {
			return "lt"
		}
	} else if op == ">" {
		if !rev {
			return "gt"
		} else {
			return "lteq"
		}
	} else if op == "<=" {
		if !rev {
			return "lteq"
		} else {
			return "gt"
		}
	} else if op == "<" {
		if !rev {
			return "lt"
		} else {
			return "gteq"
		}
	} else {
		return "eq"
	}
}

//~> 4.2.5, >= 4.2.5.1
//>= 2.12.5, < 3.0.0
//~> 3.9.5
//>= 1.9.24
var ver1Regex = regexp.MustCompile(`~> ([0-9a-zA-Z\.]+), >= ([0-9a-zA-Z\.]+)`)
var ver2Regex = regexp.MustCompile(`([\<\>\=]+) ([0-9a-zA-Z\.]+), ([\<\>\=]+) ([0-9a-zA-Z\.]+)`)
var ver3Regex = regexp.MustCompile(`~> ([0-9a-zA-Z\.]+)`)
var ver4Regex = regexp.MustCompile(`([\<\>\=]+) ([0-9a-zA-Z\.]+)`)

func parseRubyVersion(i int, pv string, rev bool) ([]common.AppModuleVersion, bool) {
	var mver common.AppModuleVersion
	if i > 0 {
		mver.OpCode = "or"
	}
	if str := ver1Regex.FindStringSubmatch(pv); len(str) > 0 {
		mver.OpCode += getOperation(">=", rev)
		// only get the first two numbers in the version as prefix
		mver.Version = str[2]
		if s := strings.Split(str[1], "."); len(s) <= 2 {
			mver.Version += "," + str[1]
		} else {
			mver.Version += "," + strings.Join(s[:2], ".")
		}
		return []common.AppModuleVersion{mver}, true
	} else if str := ver2Regex.FindStringSubmatch(pv); len(str) > 0 {
		mver.OpCode += getOperation(str[1], rev)
		mver.Version = str[2]
		// second half
		var mver2 common.AppModuleVersion
		mver2.OpCode += getOperation(str[3], rev)
		mver2.Version = str[4]
		return []common.AppModuleVersion{mver, mver2}, true
	} else if str := ver3Regex.FindStringSubmatch(pv); len(str) > 0 {
		if s := strings.Split(str[1], "."); len(s) > 0 {
			mver.OpCode += getOperation(">=", rev)
			// only get the first two numbers in the version as prefix
			mver.Version = str[1]
			if len(s) <= 2 {
				mver.Version += "," + strings.Join(s[:len(s)-1], ".")
			} else {
				mver.Version += "," + strings.Join(s[:2], ".")
			}
			return []common.AppModuleVersion{mver}, true
		} else {
			return []common.AppModuleVersion{}, false
		}
	} else if str := ver4Regex.FindStringSubmatch(pv); len(str) > 0 {
		mver.OpCode += getOperation(str[1], rev)
		mver.Version = str[2]
		return []common.AppModuleVersion{mver}, true
	} else {
		return []common.AppModuleVersion{}, false
	}
}

func generateAffectedVer(patched_versions []string) []common.AppModuleVersion {
	mvv := make([]common.AppModuleVersion, 0)
	for k, pv := range patched_versions {
		if mver, ok := parseRubyVersion(k, pv, true); ok {
			mvv = append(mvv, mver...)
		}
	}
	return mvv
}
