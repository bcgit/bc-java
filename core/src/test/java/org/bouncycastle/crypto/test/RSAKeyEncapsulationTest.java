package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.kems.RSAKEMExtractor;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the RSA Key Encapsulation Mechanism
 */
public class RSAKeyEncapsulationTest
    extends SimpleTest
{
    public String getName()
    {
        return "RSAKeyEncapsulation";
    }

    public void performTest()
        throws Exception
    {
        // Generate RSA key pair
        RSAKeyPairGenerator        rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 1024, 5));
        AsymmetricCipherKeyPair    keys   = rsaGen.generateKeyPair();
        
        // Set RSA-KEM parameters
        RSAKEMGenerator kemGen;
        RSAKEMExtractor kemExt;
        KDF2BytesGenerator        kdf = new KDF2BytesGenerator(new SHA1Digest());
        SecureRandom            rnd = new SecureRandom();
        byte[]                    out = new byte[128];
        KeyParameter            key1, key2;
        
        // Test RSA-KEM
        kemGen = new RSAKEMGenerator(128 / 8, kdf, rnd);
        
        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(keys.getPublic());
        key1 = new KeyParameter(secEnc.getSecret());
        
        kemExt = new RSAKEMExtractor((RSAKeyParameters)keys.getPrivate(), 128 / 8, kdf);
        key2 = new KeyParameter(kemExt.extractSecret(secEnc.getEncapsulation()));

        if (!areEqual(key1.getKey(), key2.getKey()))
        {
            fail("failed test");
        }

        blindingEngagedTest(keys, secEnc, key1);
        repeatedExtractionTest(keys, secEnc, key1);
        nonCrtKeyTest(keys, secEnc, key1);
        outOfRangeEncapsulationTest(keys);
    }

    /**
     * Blinding is result-preserving, so an equality check cannot tell a blinded decapsulation
     * from an unblinded one. Randomness consumption can: the blinding factor is drawn from the
     * supplied SecureRandom, so a decapsulation that draws nothing did not blind.
     */
    private void blindingEngagedTest(AsymmetricCipherKeyPair keys, SecretWithEncapsulation secEnc, KeyParameter expected)
        throws Exception
    {
        CountingSecureRandom counter = new CountingSecureRandom();

        RSAKEMExtractor kemExt = new RSAKEMExtractor(
            (RSAKeyParameters)keys.getPrivate(), 128 / 8, new KDF2BytesGenerator(new SHA1Digest()), counter);

        byte[] secret = kemExt.extractSecret(secEnc.getEncapsulation());

        if (counter.count == 0)
        {
            fail("decapsulation of a CRT key drew no randomness: private exponent operation was not blinded");
        }

        if (!areEqual(expected.getKey(), secret))
        {
            fail("blinded decapsulation recovered the wrong secret");
        }
    }

    /**
     * A fresh blinding factor is drawn per call, so a wrong unblinding step would show up as
     * decapsulations that disagree with each other.
     */
    private void repeatedExtractionTest(AsymmetricCipherKeyPair keys, SecretWithEncapsulation secEnc, KeyParameter expected)
        throws Exception
    {
        RSAKEMExtractor kemExt = new RSAKEMExtractor(
            (RSAKeyParameters)keys.getPrivate(), 128 / 8, new KDF2BytesGenerator(new SHA1Digest()));

        for (int i = 0; i != 20; i++)
        {
            if (!areEqual(expected.getKey(), kemExt.extractSecret(secEnc.getEncapsulation())))
            {
                fail("repeated blinded decapsulation disagreed at iteration " + i);
            }
        }
    }

    /**
     * A key carrying only the modulus and private exponent cannot be blinded - there is no public
     * exponent to re-encrypt the blinding factor with. Decapsulation must still succeed.
     */
    private void nonCrtKeyTest(AsymmetricCipherKeyPair keys, SecretWithEncapsulation secEnc, KeyParameter expected)
        throws Exception
    {
        RSAKeyParameters crtKey = (RSAKeyParameters)keys.getPrivate();
        RSAKeyParameters plainKey = new RSAKeyParameters(true, crtKey.getModulus(), crtKey.getExponent());

        CountingSecureRandom counter = new CountingSecureRandom();

        RSAKEMExtractor kemExt = new RSAKEMExtractor(
            plainKey, 128 / 8, new KDF2BytesGenerator(new SHA1Digest()), counter);

        if (!areEqual(expected.getKey(), kemExt.extractSecret(secEnc.getEncapsulation())))
        {
            fail("non-CRT key decapsulation recovered the wrong secret");
        }

        if (counter.count != 0)
        {
            fail("non-CRT key cannot be blinded, but randomness was drawn");
        }
    }

    /**
     * An encapsulation that is not less than the modulus is out of range for RSA-KEM and must be
     * rejected rather than exponentiated.
     */
    private void outOfRangeEncapsulationTest(AsymmetricCipherKeyPair keys)
        throws Exception
    {
        RSAKeyParameters privKey = (RSAKeyParameters)keys.getPrivate();
        BigInteger n = privKey.getModulus();

        byte[] atModulus = BigIntegers.asUnsignedByteArray((n.bitLength() + 7) / 8, n);

        RSAKEMExtractor kemExt = new RSAKEMExtractor(
            privKey, 128 / 8, new KDF2BytesGenerator(new SHA1Digest()));

        try
        {
            kemExt.extractSecret(atModulus);

            fail("out of range encapsulation accepted");
        }
        catch (DataLengthException e)
        {
            // expected
        }
    }

    private static class CountingSecureRandom
        extends SecureRandom
    {
        private final SecureRandom delegate = new SecureRandom();

        int count;

        public void nextBytes(byte[] bytes)
        {
            count++;
            delegate.nextBytes(bytes);
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new RSAKeyEncapsulationTest());
    }
}
