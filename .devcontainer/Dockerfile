ARG VARIANT="jammy"
FROM ubuntu:${VARIANT}

RUN adduser --shell /bin/bash vscode

RUN apt-get update && \
    apt-get install --no-install-recommends -y git openssh-client golang make ca-certificates gcc libc6-dev && \
    apt-get clean

RUN su - vscode -c "go install golang.org/x/tools/gopls@latest" && \
    su - vscode -c "go install github.com/go-delve/delve/cmd/dlv@latest" && \
    su - vscode -c "go install honnef.co/go/tools/cmd/staticcheck@latest" && \
    su - vscode -c "go install golang.org/x/tools/cmd/goimports@latest" && \
    su - vscode -c "go install github.com/jandelgado/gcov2lcov@latest" && \
    echo 'PATH="/home/vscode/go/bin:$PATH"' >> /home/vscode/.profile