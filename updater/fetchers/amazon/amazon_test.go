package amazon

import (
	"testing"

	"github.com/k3a/html2text"
)

var htmlBody = `
<!doctype html>
<html>
    <body class="Site">
        <main class="Site-content">
            <div class="container">
                <nav class="navbar navbar-fixed-top navbar-inverse" style="background-color: #000000" id="bs-navbar">
    <a style="font-size: 20px; color: #FF9900" class="navbar-brand" href="/"><b>Amazon Linux Security Center</b></a>
    <ul class="nav navbar-nav navbar-right" style="color: #ff9900">
    <li style="background-color: #333333;"> <a style="color: #FFFFFF" href="/index.html">Amazon Linux 1</a> </li><li style="background-color: #333333;"> <a style="color: #FFFFFF" href="/alas2.html">Amazon Linux 2</a> </li><li style="background-color: #FF9900;"> <a style="color: #000000" href="/alas2023.html">Amazon Linux 2023</a> </li><li style="background-color: #333333;"> <a style="color: #FFFFFF" href="/announcements.html">Announcements</a> </li><li style="background-color: #333333;"> <a style="color: #FFFFFF" href="/faqs.html">FAQs</a> </li>
    </ul>
</nav>
            </div>
            <div style='min-height: 523px; margin-top:80px;' class='nine columns content-with-nav' role='main'>
                <section>
                    <div class='title'>
                        <h1 id='ALAS2023-2023-368'>ALAS2023-2023-368</h1>
                    </div>

                    <div class='text'>
                        <hr class='mid-pad'>
                        <span class='alas-info'>
                            <b>Amazon Linux 2023 Security Advisory:</b> ALAS-2023-368
                        </span><br />
                        <span class='alas-info'><b>Advisory Release Date:</b> 2023-09-27 21:06 Pacific</span><br />
                        <span class='alas-info'><b>Advisory Updated Date:</b> 2023-10-03 20:50 Pacific</span><br />

                        <div id='severity' class='alas-info'>
                            <b>Severity:</b>
                            <span class='date'>
                                <span class='bulletin-type'>
                                    <i class='fas fa-exclamation-triangle'></i>
                                </span>
                            </span>
                            Important<br />
                        </div>

                        <div id='references'>
                            <b>References:</b>
                            <a href='/cve/html/CVE-2023-38039.html' target='_blank' rel='noopener noreferrer'>CVE-2023-38039&nbsp;</a>
                            <br />
                            <a href="../../faqs.html">FAQs regarding Amazon Linux ALAS/CVE Severity</a>
                        </div>

                        <hr class='mid-pad'>
                        <div id='issue_overview'>
                            <b>Issue Overview:</b>
                            <p>HTTP headers eat all memory</p><p>NOTE: https://www.openwall.com/lists/oss-security/2023/09/13/1<br />NOTE: https://curl.se/docs/CVE-2023-38039.html<br />NOTE: Introduced by: https://github.com/curl/curl/commit/7c8c723682d524ac9580b9ca3b71419163cb5660 (curl-7_83_0)<br />NOTE: Experimental tag removed in: https://github.com/curl/curl/commit/4d94fac9f0d1dd02b8308291e4c47651142dc28b (curl-7_84_0)<br />NOTE: Fixed by: https://github.com/curl/curl/commit/3ee79c1674fd6f99e8efca52cd7510e08b766770 (curl-8_3_0) (CVE-2023-38039)</p>
                        </div>

                        <div id='affected_packages' class='alas-info'>
                            <br />
                            <b>Affected Packages:</b>
                            <br />
                            <p>curl</p>
                        </div>


                        <div id='issue_correction'>
                            <br />
                            <b>Issue Correction:</b>
                            <br />Run <i>dnf update curl --releasever 2023.2.20231002</i> to update your system.<br /></div>
                        <br />
                        <div id='new_packages'>
                            <b>New Packages:</b><pre>aarch64:<br />&nbsp;&nbsp;&nbsp; libcurl-debuginfo-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; java-1.8.0-amazon-corretto-1.8.0_402.b08-1.amzn2023.aarch64<br />&nbsp;&nbsp;&nbsp; libcurl-minimal-debuginfo-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; curl-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; curl-minimal-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; curl-debuginfo-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; curl-minimal-debuginfo-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; curl-debugsource-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; libcurl-minimal-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; libcurl-8.3.0-1.amzn2023.0.1.aarch64<br />&nbsp;&nbsp;&nbsp; libcurl-devel-8.3.0-1.amzn2023.0.1.aarch64<br /><br />src:<br />&nbsp;&nbsp;&nbsp; curl-8.3.0-1.amzn2023.0.1.src<br /><br />x86_64:<br />&nbsp;&nbsp;&nbsp; curl-minimal-debuginfo-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; curl-debuginfo-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; libcurl-minimal-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; curl-minimal-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; curl-debugsource-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; libcurl-debuginfo-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; curl-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; libcurl-minimal-debuginfo-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; libcurl-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; libcurl-devel-8.3.0-1.amzn2023.0.1.x86_64<br />&nbsp;&nbsp;&nbsp; kernel-debuginfo-common-i686-4.14.336-180.562.amzn1.i686<br /></pre></div>
                    </div>
</html>`

func TestParseAlasPage(t *testing.T) {
	expectedLen := 12
	expectedVersions := map[string]string{
		"libcurl-debuginfo":            "8.3.0-1.amzn2023.0.1",
		"java-1.8.0-amazon-corretto":   "1.8.0_402.b08-1.amzn2023",
		"libcurl-minimal-debuginfo":    "8.3.0-1.amzn2023.0.1",
		"curl":                         "8.3.0-1.amzn2023.0.1",
		"curl-minimal":                 "8.3.0-1.amzn2023.0.1",
		"curl-debuginfo":               "8.3.0-1.amzn2023.0.1",
		"curl-minimal-debuginfo":       "8.3.0-1.amzn2023.0.1",
		"curl-debugsource":             "8.3.0-1.amzn2023.0.1",
		"libcurl-minimal":              "8.3.0-1.amzn2023.0.1",
		"libcurl":                      "8.3.0-1.amzn2023.0.1",
		"libcurl-devel":                "8.3.0-1.amzn2023.0.1",
		"kernel-debuginfo-common-i686": "4.14.336-180.562.amzn1",
	}
	plain := html2text.HTML2Text(string(htmlBody))
	_, vers, err := parseAlasPage("ALAS-2023-368", htmlBody, plain)
	if err != nil {
		t.Errorf("Error during parseAlasPage:%v\n", err)
	}

	//check length of version map
	if len(vers) != expectedLen {
		t.Errorf("Expected length of parseAlasPage:%v , returned length:%v\n", expectedLen, len(vers))
	}
	//Check contents of version map
	for key, value := range expectedVersions {
		val, ok := vers[key]
		if ok {
			if val != value {
				t.Errorf("parseAlasPage vers key:%s, value:%s, does not match expected value:%s,\n", key, val, value)
			}
		} else {
			t.Errorf("Missing key in vers from parseAlasPage:%s\n", key)
		}
	}
}
