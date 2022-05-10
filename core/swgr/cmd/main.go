package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/core/swgr/converter"
)

func main() {
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) != 1 {
		fmt.Println("error: usage is CMD IN-FILE")
		os.Exit(1)
	}

	dat, err := os.ReadFile(argsWithoutProg[0])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	def := &apidef.APIDefinition{}
	err = json.Unmarshal([]byte(dat), def)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s, _ := converter.TykToSwagger(def, nil)
	rawDoc, err := s[0].MarshalJSON()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(rawDoc))
}
