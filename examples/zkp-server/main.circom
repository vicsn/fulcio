pragma circom 2.0.0;

include "../../snark-jwt-verify/circuits/jwt_proof.circom";

// NOTE: a requirement for succesful proof creation/validation is that all output variables are set (and potentially tested)
// TODO: should any of the inputs be public?
component main = JwtProof(384, 8, 248, 248);
