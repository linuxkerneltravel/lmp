all:
	# go build -mod=vendor -o cmd/main cmd/main.go
	go build -o cmd/main cmd/main.go

clean:
	rm cmd/main