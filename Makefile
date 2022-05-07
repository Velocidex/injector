all:
	GOOS=windows go build -o loader.exe .

generate:
	base64 CSDump.bin.raw > CSDump.bin
	go generate
