// SPDX-FileCopyrightText: 2023 DenBond7, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.test.SimpleTest;

public class MultiThreadedSignatureVerificationTest
        extends SimpleTest {

    private static final String PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "lIYEYIq7phYJKwYBBAHaRw8BAQdAat45rrh+gvQwWwJw5eScq3Pdxt/8d+lWNVSm\n" +
            "kImXcRP+CQMCvWfx3mzDdd5g6c59LcPqADK0p70/7ZmTkp3ZC1YViTprg4tQt/PF\n" +
            "QJL+VPCG+BF9bWyFcfxKe+KAnXRTWml5O6xrv6ZkiNmAxoYyO1shzLQWZGVmYXVs\n" +
            "dEBmbG93Y3J5cHQudGVzdIh4BBMWCgAgBQJgirumAhsDBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCHgECGQEACgkQIl+AI8INCVcysgD/cu23M07rImuV5gIl98uOnSIR+QnHUD/M\n" +
            "I34b7iY/iTQBALMIsqO1PwYl2qKwmXb5lSoMj5SmnzRRE2RwAFW3AiMCnIsEYIq7\n" +
            "phIKKwYBBAGXVQEFAQEHQA8q7iPr+0OXqBGBSAL6WNDjzHuBsG7uiu5w8l/A6v8l\n" +
            "AwEIB/4JAwK9Z/HebMN13mCOF6Wy/9oZK4d0DW9cNLuQDeRVZejxT8oFMm7G8iGw\n" +
            "CGNjIWWcQSvctBZtHwgcMeplCW7tmzkD3Nq/ty50lCwQQd6gZSXMiHUEGBYKAB0F\n" +
            "AmCKu6YCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRAiX4Ajwg0JV+sbAQCv4LVM\n" +
            "0+AN54ivWa4vPRyYOfSQ1FqsipkYLJce+xwUeAD+LZpEVCypFtGWQVdeSJVxIHx3\n" +
            "k40IfHsK0fGgR+NrRAw=\n" +
            "=osuI\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final PGPSecretKeyRing secretKeyRing;

    static {
        try {
            secretKeyRing = readSecretKeyRing(PRIVATE_KEY);
        } catch (IOException | PGPException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void performTest() throws Exception {
        testBindingSignatureVerificationInThreads();
    }

    static PGPSecretKeyRing readSecretKeyRing(String armored) throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = new ArmoredInputStream(bytesIn);
        return new PGPSecretKeyRing(armorIn, new BcKeyFingerprintCalculator());
    }

    public void testBindingSignatureVerificationInThreads() throws InterruptedException {
        AtomicInteger atomicInteger = new AtomicInteger();
        int numberOfThreads = 10;
        int numberOfAttempts = 1000;
        ExecutorService service = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch latch = new CountDownLatch(numberOfThreads);
        for (int i = 0; i < numberOfThreads; i++) {
            service.submit(() -> {
                for (int j = 0; j < numberOfAttempts; j++) {
                    try {
                        isTrue(verifyBinding());
                        atomicInteger.incrementAndGet();
                    } catch (Exception e) {
                        e.printStackTrace();
                        fail(e.getMessage());
                    }
                }
                latch.countDown();
            });
        }

        isTrue(latch.await(300, TimeUnit.SECONDS));
        isEquals(numberOfThreads * numberOfAttempts, atomicInteger.get());
        service.shutdown();
    }

    private static boolean verifyBinding() throws IOException, PGPException {
        long keyId = Long.parseLong("4F1458BD22B7BB53", 16);
        PGPPublicKey subKey = secretKeyRing.getPublicKey(keyId);
        PGPPublicKey primaryKey = secretKeyRing.getPublicKey();
        PGPSignature bindingSig = subKey.getKeySignatures().next();
        PGPSignature.Verification verification = bindingSig.safeInit(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        return verification.verifyCertification(primaryKey, subKey);
    }

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }

    public static void main(String[] args) {
        runTest(new MultiThreadedSignatureVerificationTest());
    }
}
