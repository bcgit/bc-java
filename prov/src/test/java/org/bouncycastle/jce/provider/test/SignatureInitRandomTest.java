package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Signature.initSign(key) takes its randomness from the default source, not from the SecureRandom an earlier
 * initSign(key, random) on the same object was given - one service for each SignatureSpi class that randomises
 * its signatures.
 */
public class SignatureInitRandomTest
    extends SimpleTest
{
    private static final byte[] MSG = Strings.toByteArray("Hello World!");

    public String getName()
    {
        return "SignatureInitRandom";
    }

    public void performTest()
        throws Exception
    {
        checkDefaultSource("SHA256withECDSA", generateKeyPair("EC", new ECNamedCurveGenParameterSpec("P-256")));
        checkDefaultSource("SM3withSM2", generateKeyPair("EC", new ECNamedCurveGenParameterSpec("sm2p256v1")));
        checkDefaultSource("DSTU4145",
            generateKeyPair("DSTU4145", new ECNamedCurveGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2.0")));
        checkDefaultSource("ECGOST3410",
            generateKeyPair("ECGOST3410", new ECNamedCurveGenParameterSpec("GostR3410-2001-CryptoPro-A")));
        checkDefaultSource("ECGOST3410-2012-256",
            generateKeyPair("ECGOST3410-2012", new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA")));
        checkDefaultSource("ECGOST3410-2012-512",
            generateKeyPair("ECGOST3410-2012", new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA")));
        checkDefaultSource("GOST3410", generateKeyPair("GOST3410",
            new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId())));
        checkDefaultSource("SHA256withDSA", generateKeyPair("DSA", 2048));
        checkDefaultSource("SHA256withRSAandMGF1", generateKeyPair("RSA", 2048));
    }

    private void checkDefaultSource(String algorithm, KeyPair kp)
        throws Exception
    {
        CountingSecureRandom random = new CountingSecureRandom();
        Signature signer = Signature.getInstance(algorithm, "BC");

        signer.initSign(kp.getPrivate(), random);
        signer.update(MSG);
        signer.sign();

        isTrue(algorithm + ": initSign(key, random) did not draw from random", random.count > 0);

        int count = random.count;

        signer.initSign(kp.getPrivate());
        signer.update(MSG);

        byte[] sig = signer.sign();

        isEquals(algorithm + ": initSign(key) drew from the SecureRandom of an earlier init", count, random.count);

        Signature verifier = Signature.getInstance(algorithm, "BC");

        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);

        isTrue(algorithm + ": signature failed to verify", verifier.verify(sig));
    }

    private static KeyPair generateKeyPair(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        kpGen.initialize(spec, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    private static KeyPair generateKeyPair(String algorithm, int keySize)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        kpGen.initialize(keySize, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    private static class CountingSecureRandom
        extends SecureRandom
    {
        int count;

        public void nextBytes(byte[] bytes)
        {
            count++;
            super.nextBytes(bytes);
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SignatureInitRandomTest());
    }
}
