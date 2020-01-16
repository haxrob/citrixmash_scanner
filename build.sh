#!/bin/bash

VERSION=0.4
GOOS=darwin GOARCH=amd64 go build -o bin/Mac-citrixmash_scanner-v$VERSION
GOOS=linux go build -o bin/Linux-citrixmash_scanner-v$VERSION
GOOS=windows go build -o bin/Win-citrixmash_scanner-v$VERSION
