pragma circom 2.1.6;
include "circomlib/circuits/comparators.circom"; // compile with: circom2 -l node_modules

// P2P Alert Guard: release-decision circuit.
// Every signal is public on purpose: the point is a tamper-evident, zkVerify-checked
// receipt that the published APPROVE/REJECT decision is exactly what the fixed policy
// gives for the facts extracted from one specific Reclaim zkTLS proof.
//
// Public outputs: decision (1 = APPROVE_RELEASE), reasonMask (bit flags).
// Public inputs:  reclaimId (first 248 bits of the Reclaim claim identifier),
//                 refHash (first 248 bits of sha256(reference)),
//                 expectedKobo, paidKobo, statusOk, currencyOk, refUnused, liveOk.
template ReleaseDecision() {
    signal input reclaimId;
    signal input refHash;
    signal input expectedKobo;
    signal input paidKobo;
    signal input statusOk;   // Paystack data.status == "success"
    signal input currencyOk; // data.currency == "NGN"
    signal input refUnused;  // reference never approved for another trade
    signal input liveOk;     // live-mode payment, or test mode allowed by config
    signal output decision;
    signal output reasonMask;

    statusOk * (statusOk - 1) === 0;
    currencyOk * (currencyOk - 1) === 0;
    refUnused * (refUnused - 1) === 0;
    liveOk * (liveOk - 1) === 0;

    // amounts must fit in 64 bits so equality is meaningful
    component rp = Num2Bits(64); rp.in <== paidKobo;
    component re = Num2Bits(64); re.in <== expectedKobo;
    component eq = IsEqual(); eq.in[0] <== paidKobo; eq.in[1] <== expectedKobo;
    signal amountOk; amountOk <== eq.out;

    // bind identifiers into the constraint system (non-zero)
    component z1 = IsZero(); z1.in <== reclaimId; z1.out === 0;
    component z2 = IsZero(); z2.in <== refHash;  z2.out === 0;

    signal a; a <== statusOk * amountOk;
    signal b; b <== a * currencyOk;
    signal c; c <== b * refUnused;
    decision <== c * liveOk;

    // bit0 NOT_SUCCESS, bit1 AMOUNT_MISMATCH, bit2 CURRENCY_MISMATCH, bit3 REFERENCE_REUSED, bit4 TEST_MODE
    reasonMask <== (1 - statusOk) + 2 * (1 - amountOk) + 4 * (1 - currencyOk) + 8 * (1 - refUnused) + 16 * (1 - liveOk);
}
component main {public [reclaimId, refHash, expectedKobo, paidKobo, statusOk, currencyOk, refUnused, liveOk]} = ReleaseDecision();
