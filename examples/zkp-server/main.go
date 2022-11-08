// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type FulcioZkpConfig struct {
	ZkeyPath    string `json:"zkeypath,omitempty"`
	VkeyPath    string `json:"vkeypath,omitempty"`
	ProofPath   string `json:"proofpath,omitempty"`
	WitnessPath string `json:"witnesspath,omitempty"`
	PublicPath  string `json:"publicpath,omitempty"`
	InputPath   string `json:"inputpath,omitempty"`
	ProofSystem string `json:"proofsystem,omitempty"`
}

type ProveRequest struct {
	Payload []uint `json:"payload,omitempty"`
	Mask    []uint `json:"mask,omitempty"`
	Tblock  uint8  `json:"tblock,omitempty"`
}

var (
	zkpGeneratorHost = "localhost"
	zkpGeneratorPort = "3333"
	configPath       = "config.json"
)

func proveClaimZkp(w http.ResponseWriter, req *http.Request, config *FulcioZkpConfig) {
	fmt.Println("Starting to prove zkp")

	payload := ProveRequest{}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = json.Unmarshal(body, &payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = os.WriteFile(config.InputPath, body, 0600)
	if err != nil {
		fmt.Println(err)
		return
	}

	var out bytes.Buffer

	start := time.Now()

	cmd := exec.Command("node", "build/main_js/generate_witness.js", "build/main_js/main.wasm", config.InputPath, "build/witness.wtns")
	cmd.Stdout = &out
	err = cmd.Run()

	if err != nil {
		fmt.Println("error generating witness: ", err)
		return
	}
	fmt.Println("Generated witnessfile")

	cmd = exec.Command("../../snark-jwt-verify/node_modules/snarkjs/build/cli.cjs", config.ProofSystem, "prove", config.ZkeyPath, config.WitnessPath, config.ProofPath, config.PublicPath)
	cmd.Stdout = &out
	err = cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		fmt.Println("error proving: ", err)
		return
	}
	log.Printf("Proving took %s", elapsed)
	fmt.Printf("Proved output: %q\n", out.String())
}

func verifyClaimZkp(w http.ResponseWriter, req *http.Request, config *FulcioZkpConfig) {
	fmt.Println("Starting to verify zkp")
	cmd := exec.Command("../../snark-jwt-verify/node_modules/snarkjs/build/cli.cjs", config.ProofSystem, "verify", config.VkeyPath, config.PublicPath, config.ProofPath)

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()

	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	fmt.Printf("Verified output: %q\n", out.String())
}

func main() {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatal(err)
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &FulcioZkpConfig{}
	if err := json.Unmarshal(b, cfg); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/prove", func(w http.ResponseWriter, req *http.Request) {
		proveClaimZkp(w, req, cfg)
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, req *http.Request) {
		verifyClaimZkp(w, req, cfg)
	})
	fmt.Printf("zkp-server ready and listening on %s:%s\n", zkpGeneratorHost, zkpGeneratorPort)
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", zkpGeneratorPort),
		Handler: mux,
	}
	log.Fatal(srv.ListenAndServe())
}
