# go-sse-notifier

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags netgo -ldflags "-s -w" -o app ./cmd/sse-notifier

# go-discord-bot

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags netgo -ldflags "-s -w" -o app ./cmd/discord-bot
