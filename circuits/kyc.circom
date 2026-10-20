pragma circom 2.2.3;
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

template LocalKYC(depth) {
    signal output response;
    signal input issuerRoot;
    signal input currentTime;
    signal input validUntil;
    signal input context;
    signal input issuerId;
    signal input policyId;
    signal input u[13];
    signal input secret;
    signal input verified;
    signal input issuedAt;
    signal input expiry;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    verified === 1;
    component nonzero = IsZero();
    nonzero.in <== secret;
    nonzero.out === 0;
    component t0=Num2Bits(32);
    component t1=Num2Bits(32);
    component t2=Num2Bits(32);
    component t3=Num2Bits(32);
    t0.in <== issuedAt; t1.in <== currentTime; t2.in <== expiry;
    t3.in <== validUntil;
    component started=LessEqThan(32);
    started.in[0] <== issuedAt; started.in[1] <== currentTime;
    started.out === 1;
    component valid=LessEqThan(32);
    valid.in[0] <== validUntil; valid.in[1] <== expiry;
    valid.out === 1;
    component window=LessEqThan(32);
    window.in[0] <== currentTime; window.in[1] <== validUntil;
    window.out === 1;

    component digest=Poseidon(13);
    for(var i=0;i<13;i++) digest.inputs[i] <== u[i];
    component holder=Poseidon(2);
    holder.inputs[0] <== 202610201; holder.inputs[1] <== secret;
    component credential=Poseidon(8);
    credential.inputs[0] <== 202610202;
    credential.inputs[1] <== digest.out;
    credential.inputs[2] <== holder.out;
    credential.inputs[3] <== issuedAt;
    credential.inputs[4] <== expiry;
    credential.inputs[5] <== verified;
    credential.inputs[6] <== issuerId;
    credential.inputs[7] <== policyId;

    signal nodes[depth+1];
    signal left[depth]; signal right[depth];
    component branches[depth];
    nodes[0] <== credential.out;
    for(var j=0;j<depth;j++) {
        pathIndices[j]*(pathIndices[j]-1) === 0;
        left[j] <== nodes[j]+pathIndices[j]*(pathElements[j]-nodes[j]);
        right[j] <== pathElements[j]+pathIndices[j]*(nodes[j]-pathElements[j]);
        branches[j]=Poseidon(2);
        branches[j].inputs[0] <== left[j]; branches[j].inputs[1] <== right[j];
        nodes[j+1] <== branches[j].out;
    }
    nodes[depth] === issuerRoot;
    component bound=Poseidon(3);
    bound.inputs[0] <== 202610203; bound.inputs[1] <== secret; bound.inputs[2] <== context;
    response <== bound.out;
}
// Public signal order: response, issuerRoot, currentTime, validUntil, context, issuerId, policyId.
component main {public [issuerRoot,currentTime,validUntil,context,issuerId,policyId]}=LocalKYC(12);
