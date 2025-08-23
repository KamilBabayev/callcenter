app_name=callcenter

build:
	go build -o $(app_name) ./main.go

run:
	go run ./main.go

clean:
	rm -f $(app_name)