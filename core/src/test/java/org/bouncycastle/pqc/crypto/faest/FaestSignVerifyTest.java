package org.bouncycastle.pqc.crypto.faest;

import java.util.Random;

import org.bouncycastle.util.test.SimpleTest;

/**
 * End-to-end FAEST sign/verify round-trip. Generates a fresh OWF key + input,
 * computes the OWF output (AES-128 encryption for FAEST-128-S), signs a random
 * message, and verifies. Success means the entire FAEST pipeline — VOLE
 * commit, BAVC, witness extension, AES constraints, and the transcript hashes —
 * is end-to-end consistent.
 */
public class FaestSignVerifyTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestSignVerify";
    }

    public void performTest()
        throws Exception
    {
        roundtrip(FaestParameters.faest_128s, 0x100L);
        roundtrip(FaestParameters.faest_192s, 0x101L);
        roundtrip(FaestParameters.faest_256s, 0x102L);
    }

    private void roundtrip(FaestParameters p, long seed)
        throws Exception
    {
        Random rng = new Random(seed);

        byte[] owfKey = new byte[p.getLambdaBytes()];
        rng.nextBytes(owfKey);
        byte[] owfInput = new byte[p.getOwfInputSize()];
        rng.nextBytes(owfInput);
        byte[] owfOutput = new byte[p.getOwfOutputSize()];
        encryptOwf(owfKey, owfInput, owfOutput, p);

        byte[] msg = new byte[42];
        rng.nextBytes(msg);
        byte[] rho = new byte[16]; rng.nextBytes(rho);

        byte[] sig = new byte[p.getSigSize()];
        long t0 = System.currentTimeMillis();
        Faest.sign(sig, msg, owfKey, owfInput, owfOutput, rho, p);
        long t1 = System.currentTimeMillis();

        int rc = Faest.verify(msg, sig, owfInput, owfOutput, p);
        long t2 = System.currentTimeMillis();

        System.out.println("  " + p.getName() + ": sign=" + (t1 - t0) + "ms verify=" + (t2 - t1)
            + "ms sig=" + sig.length + " bytes rc=" + rc);
        isTrue(p.getName() + " sign/verify round-trip rc==0", rc == 0);
    }

    /** Compute owfOutput = AES_lambda(owfKey, owfInput) [|| AES_lambda(owfKey, owfInput XOR 1)] */
    private static void encryptOwf(byte[] owfKey, byte[] owfInput, byte[] owfOutput, FaestParameters p)
    {
        int lambda = p.getLambda();
        if (lambda == 128)
        {
            FaestAES.aes128EncryptBlock(owfKey, 0, owfInput, 0, owfOutput, 0);
        }
        else if (lambda == 192)
        {
            FaestAES.aes192EncryptBlock(owfKey, 0, owfInput, 0, owfOutput, 0);
            byte[] in2 = owfInput.clone();
            in2[0] ^= 0x01;
            FaestAES.aes192EncryptBlock(owfKey, 0, in2, 0, owfOutput, 16);
        }
        else
        {
            FaestAES.aes256EncryptBlock(owfKey, 0, owfInput, 0, owfOutput, 0);
            byte[] in2 = owfInput.clone();
            in2[0] ^= 0x01;
            FaestAES.aes256EncryptBlock(owfKey, 0, in2, 0, owfOutput, 16);
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new FaestSignVerifyTest());
    }
}
