package utils

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

func Encrypt(encryptionKey, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return ciphertext, nil
}

func GzipBytes(buf []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(buf)
	w.Close()

	return b.Bytes()
}

func GunzipBytes(buf []byte) []byte {
	b := bytes.NewBuffer(buf)
	r, err := gzip.NewReader(b)
	if err != nil {
		return nil
	}
	defer r.Close()
	uzb, _ := ioutil.ReadAll(r)
	return uzb
}

func GetCaller(skip int, excludes []string) string {
	var fn string

	pc := make([]uintptr, 20)
	n := runtime.Callers(skip, pc)
OUTER:
	for i := 0; i < n; i++ {
		fpath := runtime.FuncForPC(pc[i]).Name()
		// fmt.Printf("********  %s\n", fpath)
		for _, exclude := range excludes {
			if strings.Contains(fpath, exclude) {
				continue OUTER
			}
		}
		slash := strings.LastIndex(fpath, "/")
		if slash == -1 {
			fn = fpath
		} else {
			fn = fpath[slash+1:]
		}
		return fn
	}

	return fn
}

// -- Logger

type LogFormatter struct {
	Module string
}

func (f *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	// Skip 2, 0: callers(), 1: GetCaller, 2: LogFormatter()
	fn := GetCaller(3, []string{"logrus"})

	var keys []string = make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	b := &bytes.Buffer{}

	fmt.Fprintf(b, "%-23s", entry.Time.Format("2006-01-02T15:04:05.999"))
	fmt.Fprintf(b, "|%s|%s|%s:",
		strings.ToUpper(entry.Level.String())[0:4], f.Module, fn)
	if len(entry.Message) > 0 {
		fmt.Fprintf(b, " %s", entry.Message)
	}
	if len(keys) > 0 {
		fmt.Fprintf(b, " - ")
		for i, key := range keys {
			b.WriteString(key)
			b.WriteByte('=')
			fmt.Fprintf(b, "%+v", entry.Data[key])
			if i < len(keys)-1 {
				b.WriteByte(' ')
			}
		}
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

// --

// Exec runs the given binary with arguments
func Exec(dir string, bin string, args ...string) ([]byte, error) {
	_, err := exec.LookPath(bin)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	return buf.Bytes(), err
}
