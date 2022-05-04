all:
	GOOS=windows go build -o loader.exe .

generate:
	go generate
