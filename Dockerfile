FROM alpine:edge AS build
RUN apk add --no-cache go
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
ARG VERSION=dev
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/sealed-secrets-mcp .

FROM alpine:edge
RUN apk add --no-cache ca-certificates
COPY --from=build /out/sealed-secrets-mcp /usr/local/bin/sealed-secrets-mcp
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sealed-secrets-mcp"]
CMD ["serve"]
