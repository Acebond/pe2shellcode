package main

import (
	"fmt"
	"log"
	"os"

	peparser "github.com/saferwall/pe"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("pe2shellcode pe.exe shellcode.bin\n")
		return
	}

	pe, err := peparser.New(os.Args[1], &peparser.Options{})
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", os.Args[1], err)
	}
	defer pe.Close()

	outfile, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", os.Args[2], err.Error())
	}
	defer outfile.Close()

	if err = pe.Parse(); err != nil {
		log.Fatalf(err.Error())
	}

	for _, sec := range pe.Sections {
		if sec.String() == ".text" {
			fmt.Printf("[*] %s Section: \n", sec.Header.Name)
			fmt.Printf("    [*] VirtualAddress : 0x%x\n", sec.Header.VirtualAddress)
			fmt.Printf("    [*] VirtualSize    : %v\n", sec.Header.VirtualSize)
			fmt.Printf("    [*] SizeOfRawData  : %v\n", sec.Header.SizeOfRawData)

			shellcode := sec.Data(sec.Header.VirtualAddress, sec.Header.VirtualSize, pe)
			_, err := outfile.Write(shellcode)
			if err != nil {
				fmt.Println(err.Error())
			}
			break
		}
	}
}
