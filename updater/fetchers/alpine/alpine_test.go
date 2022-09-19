package alpine

import (
	"testing"

	"io/ioutil"
	"regexp"
)

func TestParseSecDbIndex(t *testing.T) {
	index := `
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="v3.10/">v3.10/</a>                                             15-Dec-2020 13:14       -
<a href="v3.11/">v3.11/</a>                                             15-Dec-2020 13:14       -
<a href="v3.12/">v3.12/</a>                                             18-Dec-2020 21:09       -
<a href="v3.2/">v3.2/</a>                                              18-Dec-2020 13:57       -
<a href="v3.3/">v3.3/</a>                                              20-Oct-2020 08:25       -
<a href="v3.4/">v3.4/</a>                                              20-Oct-2020 08:44       -
<a href="v3.5/">v3.5/</a>                                              20-Oct-2020 09:04       -
<a href="v3.6/">v3.6/</a>                                              20-Oct-2020 10:41       -
<a href="v3.7/">v3.7/</a>                                              20-Oct-2020 11:56       -
<a href="v3.8/">v3.8/</a>                                              20-Oct-2020 12:50       -
<a href="v3.9/">v3.9/</a>                                              14-Dec-2020 10:20       -
</pre><hr></body>
</html>
`
	var nsRegexp = regexp.MustCompile(`<a href="v.*/">(.*)/</a>.*-`)
	matches := nsRegexp.FindAllStringSubmatch(index, -1)

	var count int
	for _, m := range matches {
		if len(m) == 2 && len(m[1]) > 0 {
			count++
		}
	}
	if count != 11 {
		t.Errorf("Count namespaces error: %v", count)
	}
}

func TestParseSecDb(t *testing.T) {
	filename := "secdb36main"
	body, _ := ioutil.ReadFile(filename)

	if _, err := parseSecDB(body, filename); err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
}
