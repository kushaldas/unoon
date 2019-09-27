package main

import (
	"fmt"
	"time"
)

var PDB ProcessDB

func main() {

	PDB = processMap()

	for {
		time.Sleep(2 * time.Second)
		allps := processMap()
		// Now check which all processes no longer exists
		for k, v := range allps {
			_, ok := PDB[k]
			if ok == false {
				// Mark this process as new
				fmt.Printf("%#v\n", v)

			}
		}
		// Replace the old map
		// hello
		PDB = allps

	}

}
