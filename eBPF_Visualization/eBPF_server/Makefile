all:
	go build -o lmp-server cmd/server/main.go
	go build -o lmp-cli cmd/cli/main.go

vendor:
	go build -mod=vendor -o lmp-server cmd/server/main.go
	go build -mod=vendor -o lmp-cli cmd/cli/main.go

clean:
	rm -rf lmp-server lmp-cli
