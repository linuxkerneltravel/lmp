all:
	go build -o lmp-server cmd/server/main.go
	go build -o lmp-cli cmd/cli/main.go
	sh ./init_sqlite_database.sh
vendor:
	go build -mod=vendor -o lmp-server cmd/server/main.go
	go build -mod=vendor -o lmp-cli cmd/cli/main.go
	sh ./init_sqlite_database.sh

clean:
	rm -rf lmp-server lmp-cli
	rm -rf model/data_collector/dao/tables