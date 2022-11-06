fulcio examples
===============

This directory contains example code that shows how one utilize the fulcio
library for certificate generation.

# request-certificate
This code is a minimal example how one would request a short-lived certificate
(20 minutes) for code signing. It uses the fulcio oauth portal and generates a
RSA 4096 key.

# zkp-server
This code is a proof of concept showing how a zero-knowledge proof can be made
about a claim, allowing for publication of proven details and reducing trust in
fulcio. It requires the following setup first - [see the snarkjs documentation for more details](https://github.com/iden3/snarkjs):
```
git submodule update --init --recursive
cd examples/zkp-server
mkdir -p build
circom "main.circom" --r1cs --wasm --sym --output build
../../snark-jwt-verify/node_modules/snarkjs/build/cli.cjs groth16 setup build/main.r1cs $powersoftaufile build/circuit_final.zkey
./node_modules/snarkjs/build/cli.cjs zkey export verificationkey build/circuit_final.zkey build/verification_key.json
```

Next, you can run the program and test it:
```
go run main.go
curl localhost:3333/prove -d @input.json
```

In the current Fulcio setup, third parties need to trust Fulcio that it correctly verifies client OIDC tokens. An easy solution would be to make the token public in e.g. a transparency log, but this would hurt privacy. This issue can be solved if Fulcio publishes not the signed OIDC token, but instead, only the signature, the public parts of the OIDC token and a zero-knowledge proof of knowledge that those public parts were signed by the posted signature. Public witness fields of the hashed JWT preimage to prove include: "iss", "aud", "exp", "iat", "nonce", "at_hash", "c_hash", and "email_verified". The zero-knowledge proof can be posted into a transparency log in order to be publicly verifiable.