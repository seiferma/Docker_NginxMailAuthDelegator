ARG VERSION
FROM golang:1.26-alpine

RUN adduser --disabled-password vscode

RUN apk update && apk add git openssh-client make ca-certificates gcc musl-dev
RUN go install golang.org/x/tools/gopls@latest
RUN go install github.com/go-delve/delve/cmd/dlv@latest
RUN go install honnef.co/go/tools/cmd/staticcheck@latest
RUN go install golang.org/x/tools/cmd/goimports@latest
RUN go install github.com/jandelgado/gcov2lcov@latest

RUN apk add --no-cache curl bash
RUN mkdir /home/vscode/.local && \
    chown vscode:vscode /home/vscode/.local
