package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("The program directory is %s\n", os.Args[0])
	if len(os.Args) > 1 {
		fmt.Println("The command line arguments are:")
		for i, arg := range os.Args[1:] {
			fmt.Printf("arg %d: %s\n", i+1, arg)
		}
	} else {
		fmt.Println("No command line arguments provided.")
	}
}
