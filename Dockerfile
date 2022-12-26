FROM golang:alpine AS builder
RUN apk add --no-cache make ca-certificates git
WORKDIR /go/src/app
COPY . .
RUN make RELEASE=1 build test

FROM scratch
COPY --from=builder /go/src/app/build/nginx-mail-auth-delegator /opt/nginx-mail-auth-delegator
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 8080
ENTRYPOINT ["/opt/nginx-mail-auth-delegator"]