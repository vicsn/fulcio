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
)

type FulcioZkpConfig struct {
	ZkeyPath    string `json:"zkeypath,omitempty"`
	VkeyPath    string `json:"vkeypath,omitempty"`
	ProofPath   string `json:"proofpath,omitempty"`
	WitnessPath string `json:"witnesspath,omitempty"`
	PublicPath  string `json:"publicpath,omitempty"`
	InputPath   string `json:"inputpath,omitempty"`
}

type ProveRequest struct {
	Payload []uint8 `json:"payload,omitempty"`
	Mask    []uint8 `json:"mask,omitempty"`
	Tblock  uint8   `json:"tblock,omitempty"`
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
	file, _ := json.Marshal(payload)
	_ = os.WriteFile(config.InputPath, file, 0600)

	var out bytes.Buffer

	cmd := exec.Command("node", "build/main_js/generate_witness.js", "build/main_js/main.wasm", config.InputPath, "build/witness.wtns")
	cmd.Stdout = &out
	err = cmd.Run()

	if err != nil {
		fmt.Println("error generating witness: ", err)
		return
	}
	fmt.Println("Generated witnessfile")

	cmd = exec.Command("../../snark-jwt-verify/node_modules/snarkjs/build/cli.cjs", "groth16", "prove", config.ZkeyPath, config.WitnessPath, config.ProofPath, config.PublicPath)
	cmd.Stdout = &out
	err = cmd.Run()

	if err != nil {
		fmt.Println("error proving: ", err)
		return
	}

	fmt.Printf("Proved output: %q\n", out.String())
}

func verifyClaimZkp(w http.ResponseWriter, req *http.Request, config *FulcioZkpConfig) {
	fmt.Println("Starting to verify zkp")
	cmd := exec.Command("../../snark-jwt-verify/node_modules/snarkjs/build/cli.cjs", "groth16", "verify", config.VkeyPath, config.PublicPath, config.ProofPath)

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
