package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.engines.CramerShoupCiphertext;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine.CramerShoupCiphertextException;
import org.bouncycastle.crypto.generators.CramerShoupKeyPairGenerator;
import org.bouncycastle.crypto.generators.CramerShoupParametersGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.CramerShoupKeyGenerationParameters;
import org.bouncycastle.crypto.params.CramerShoupParameters;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

public class CramerShoupTest
    extends SimpleTest
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private static final SecureRandom RND = new SecureRandom();

    private AsymmetricCipherKeyPair keyPair;

    public static void main(String[] args)
    {
        runTest(new CramerShoupTest());
    }

    public String getName()
    {
        return "CramerShoup";
    }


    public void performTest()
        throws Exception
    {
        BigInteger pSubOne = DHStandardGroups.rfc3526_2048.getP().subtract(ONE);
        for (int i = 0; i < 10; ++i)
        {
            BigInteger message = BigIntegers.createRandomInRange(ONE, pSubOne, RND);

            BigInteger m1 = encDecTest(message);
            BigInteger m2 = labelledEncDecTest(message, "myRandomLabel");
            BigInteger m3 = encDecEncodingTest(message);
            BigInteger m4 = labelledEncDecEncodingTest(message, "myOtherCoolLabel");

            if (!message.equals(m1) || !message.equals(m2) || !message.equals(m3) || !message.equals(m4))
            {
                fail("decrypted message != original message");
            }
        }

        testRepeatedDecryptionAgrees();
        testDegenerateCiphertextRejected();
    }

    /**
     * Decryption blinds each private exponent with a fresh random multiple of p-1 per call, which
     * leaves the recovered message alone only if the multiple really is of the group order, so drive
     * repeated decryptions of one ciphertext and require they all agree.
     */
    private void testRepeatedDecryptionAgrees()
        throws Exception
    {
        BigInteger pSubOne = DHStandardGroups.rfc3526_2048.getP().subtract(ONE);
        BigInteger message = BigIntegers.createRandomInRange(ONE, pSubOne, RND);

        CramerShoupCiphertext cipherText = encrypt(message, null);

        // decryption is initialised through ParametersWithRandom, so the blinding must draw from the
        // random the caller supplied - the engine used to ask initSecureRandom for one only when
        // encrypting, leaving the field null on this path
        CountingRandom counting = new CountingRandom(RND);

        CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
        engine.init(false, new ParametersWithRandom(keyPair.getPrivate(), counting));

        for (int rep = 0; rep != 12; rep++)
        {
            counting.count = 0;

            if (!message.equals(engine.decryptBlock(cipherText)))
            {
                fail("repeated blinded decryption disagreed at iteration " + rep);
            }

            // two exponents in the correctness check plus the one recovering the message
            if (counting.count != 3)
            {
                fail("decryption did not blind all three exponents from the caller's SecureRandom"
                    + " (iteration " + rep + ", draws " + counting.count + ")");
            }
        }
    }

    private static class CountingRandom
        extends SecureRandom
    {
        private final SecureRandom delegate;

        int count;

        CountingRandom(SecureRandom delegate)
        {
            this.delegate = delegate;
        }

        public void nextBytes(byte[] bytes)
        {
            count++;
            delegate.nextBytes(bytes);
        }
    }

    /**
     * An all-zero ciphertext satisfies the correctness check - zero to any power is zero, so the
     * recomputed v matches a supplied v of zero - and then used to reach modInverse(0), which does not
     * exist, so an unchecked ArithmeticException escaped a method declaring only
     * CramerShoupCiphertextException. u1 and u2 are now range-checked first.
     */
    private void testDegenerateCiphertextRejected()
        throws Exception
    {
        BigInteger pSubOne = DHStandardGroups.rfc3526_2048.getP().subtract(ONE);
        BigInteger message = BigIntegers.createRandomInRange(ONE, pSubOne, RND);

        encrypt(message, null);       // just to populate keyPair

        CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
        engine.init(false, keyPair.getPrivate());

        BigInteger[] bad = new BigInteger[]{BigInteger.ZERO, ONE, pSubOne, DHStandardGroups.rfc3526_2048.getP()};

        for (int i = 0; i != bad.length; i++)
        {
            try
            {
                engine.decryptBlock(new CramerShoupCiphertext(bad[i], bad[i], bad[i], bad[i]));

                fail("degenerate ciphertext accepted for u1 = u2 = " + bad[i].bitLength() + " bits");
            }
            catch (CramerShoupCiphertextException e)
            {
                // expected - and specifically not an ArithmeticException
            }
        }
    }

    private BigInteger encDecEncodingTest(BigInteger m)
    {
        CramerShoupCiphertext ciphertext = encrypt(m);
        byte[] c = ciphertext.toByteArray();
        CramerShoupCiphertext decC = new CramerShoupCiphertext(c);
        return decrypt(decC);
    }

    private BigInteger labelledEncDecEncodingTest(BigInteger m, String l)
    {
        byte[] c = encrypt(m, l).toByteArray();
        return decrypt(new CramerShoupCiphertext(c), l);
    }

    private BigInteger encDecTest(BigInteger m)
    {
        CramerShoupCiphertext c = encrypt(m);
        return decrypt(c);
    }

    private BigInteger labelledEncDecTest(BigInteger m, String l)
    {
        CramerShoupCiphertext c = encrypt(m, l);
        return decrypt(c, l);
    }


    private BigInteger decrypt(CramerShoupCiphertext ciphertext)
    {
        return decrypt(ciphertext, null);
    }

    private BigInteger decrypt(CramerShoupCiphertext ciphertext, String label)
    {

        CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
        if (label != null)
        {
            engine.init(false, keyPair.getPrivate(), label);
        }
        else
        {
            engine.init(false, keyPair.getPrivate());
        }
        try
        {
            BigInteger m = engine.decryptBlock(ciphertext);

            return m;
        }
        catch (CramerShoupCiphertextException e)
        {
            e.printStackTrace();
        }

        return null;
    }

    private CramerShoupCiphertext encrypt(BigInteger message)
    {
        return encrypt(message, null);
    }

    private CramerShoupCiphertext encrypt(BigInteger message, String label)
    {
        CramerShoupKeyPairGenerator kpGen = new CramerShoupKeyPairGenerator();
        CramerShoupParametersGenerator pGen = new CramerShoupParametersGenerator();

        pGen.init(2048, 1, RND);
        CramerShoupParameters params = pGen.generateParameters(DHStandardGroups.rfc3526_2048);
        CramerShoupKeyGenerationParameters param = new CramerShoupKeyGenerationParameters(RND, params);

        kpGen.init(param);
        keyPair = kpGen.generateKeyPair();

        CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
        if (label != null)
        {
            engine.init(true, keyPair.getPublic(), label);
        }
        else
        {
            engine.init(true, keyPair.getPublic());
        }

        CramerShoupCiphertext ciphertext = engine.encryptBlock(message);

        return ciphertext;
    }
}
