package main

import (
	"fmt"
	"time"

	"github.com/kushaldas/unoon/pkg/localprocess"
)

var PDB localprocess.ProcessDB

func main() {

	PDB = localprocess.ProcessMap()

	for {
		time.Sleep(2 * time.Second)
		allps := localprocess.ProcessMap()
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
