package co.edu.icesi.signer.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class VerificationResultTest {

    @Test
    void exitCodesFollowCliContract() {
        assertEquals(0, VerificationResult.VALID.exitCode());
        assertEquals(1, VerificationResult.INVALID.exitCode());
        assertEquals(2, VerificationResult.ERROR.exitCode());
    }

    @Test
    void hasExactlyThreeOutcomes() {
        assertEquals(3, VerificationResult.values().length);
    }
}
