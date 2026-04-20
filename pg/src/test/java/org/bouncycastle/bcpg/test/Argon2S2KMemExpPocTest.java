package org.bouncycastle.bcpg.test;

import java.io.IOException;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.Assert;
import org.junit.Test;

/**
 * PGP S2K Argon2 memorySizeExponent OOM.
 *
 * poc_argon2_s2k.pgp is a crafted 24-byte PGP SKESK v4 packet with
 * memorySizeExponent=22 (4 GiB). Without the fix, S2K wire parsing
 * (S2K.java) accepted any byte value (0-255), allowing
 * Argon2BytesGenerator.init() to allocate 4,194,304 Block objects
 * (each long[128] = 1 KB) => OutOfMemoryError.
 *
 * Stack trace (pre-fix):
 *   java.lang.OutOfMemoryError: Java heap space
 *       at Argon2BytesGenerator$Block.<init>
 *       at Argon2BytesGenerator.init
 *
 * Fix: wire parser enforces MAX_ARGON2_MEMORY_EXP (default 21, configurable via
 * -Dorg.bouncycastle.openpgp.argon2.max_memory_exp). The crafted packet
 * (memExp=22) is rejected at parse time with IOException => no memory allocated.
 */
public class Argon2S2KMemExpPocTest {

    /**
     * Confirms the pre-fix behaviour: passing memExp=22 directly to
     * Argon2BytesGenerator (bypassing the wire parser) causes OutOfMemoryError.
     * Reproduces the vulnerability without the wire-parse guard.
     */
    @Test
    public void withoutFix_craftedPacketCausesOom() {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(new byte[16])
            .withIterations(1)
            .withParallelism(1)
            .withMemoryPowOfTwo(22)          // 1 << 22 KiB = 4 GiB, no guard
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .build();

        try {
            new Argon2BytesGenerator().init(params);  // 4,194,304 × 1 KB blocks => OOM
            Assert.fail("expected OutOfMemoryError");
        } catch (OutOfMemoryError e) {
            // confirmed: heap exhausted before any key derivation runs
        }
    }

    /**
     * Fix verification — the same crafted packet that caused OOM is now
     * rejected at wire-parse time with IOException. No Argon2 memory is allocated.
     *
     * Default cap: 21 (configurable via -Dorg.bouncycastle.openpgp.argon2.max_memory_exp).
     * poc_argon2_s2k.pgp has memorySizeExponent=22, which exceeds the default cap.
     */
    @Test
    public void withFix_samePacketThrowsIOExceptionNotOom() throws Exception {
        BCPGInputStream pgpIn = new BCPGInputStream(
            getClass().getResourceAsStream("poc_argon2_s2k.pgp"));

        try {
            pgpIn.readPacket();  // throws IOException at parse time, no Argon2 allocation
            Assert.fail("expected IOException for memorySizeExponent=22");
        } catch (IOException e) {
            Assert.assertTrue(
                "expected message to contain 'memorySizeExponent', got: " + e.getMessage(),
                e.getMessage().contains("memorySizeExponent"));
        }
    }
}
