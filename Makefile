.PHONY: dbgen

STAGE_DIR = stage
BUILD_IMAGE_TAG = v2

all:
	go build -ldflags='-s -w' -o dbgen -buildvcs=false
db:
	@echo "Making $@ ..."
	@docker pull neuvector/build_fleet:${BUILD_IMAGE_TAG}
	@docker run --rm -ia STDOUT --name build -e VULN_VER=$(VULN_VER) -e NVD_KEY=$(NVD_KEY) -v $(CURDIR):/go/src/github.com/neuvector/vul-dbgen -w /go/src/github.com/neuvector/vul-dbgen --entrypoint ./make_db.sh neuvector/build_fleet:${BUILD_IMAGE_TAG}
