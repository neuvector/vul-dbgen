.PHONY: dbgen

STAGE_DIR = stage

all:
	go build -ldflags='-s -w' -o dbgen

db:
	@echo "Making $@ ..."
	@docker pull neuvector/build_fleet
	@docker run --rm -ia STDOUT --name build -e VULN_VER=$(VULN_VER) -v $(CURDIR):/go/src/github.com/neuvector/vul-dbgen -w /go/src/github.com/neuvector/vul-dbgen --entrypoint ./make_db.sh neuvector/build_fleet
