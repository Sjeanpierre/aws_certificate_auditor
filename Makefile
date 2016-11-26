# Builds and packages go application for use with AWS lambda 
all: clean build package post

clean:
	@echo "removing previous package"
	@rm -f cert_auditor.zip

build:
	@echo "building binary for use with lambda"
	@GOARCH=amd64 GOOS=linux go build -o ./lambda/cert_auditor

package:
	@echo "building package cert-auditor.zip for upload to lambda"
	@zip -r -j cert_auditor.zip lambda/*

post:
	@echo "deleting binary from build step"
	@rm -f ./lambda/cert_auditor

.PHONY: all clean post
