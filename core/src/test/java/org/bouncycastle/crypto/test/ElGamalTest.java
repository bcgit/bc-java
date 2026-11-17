package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ElGamalTest
    extends SimpleTest
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    private BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
    private BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

    private BigInteger  g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger  p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

    public String getName()
    {
        return "ElGamal";
    }

    private void testEnc(
        int         size,
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
    {
        ElGamalParameters                dhParams = new ElGamalParameters(p, g, privateValueSize);
        ElGamalKeyGenerationParameters   params = new ElGamalKeyGenerationParameters(new SecureRandom(), dhParams);
        ElGamalKeyPairGenerator          kpGen = new ElGamalKeyPairGenerator();

        kpGen.init(params);

        //
        // generate pair
        //
        AsymmetricCipherKeyPair         pair = kpGen.generateKeyPair();

        ElGamalPublicKeyParameters      pu = (ElGamalPublicKeyParameters)pair.getPublic();
        ElGamalPrivateKeyParameters     pv = (ElGamalPrivateKeyParameters)pair.getPrivate();

        checkKeySize(privateValueSize, pv);

        ElGamalEngine    e = new ElGamalEngine();

        e.init(true, pu);
        
        if (e.getOutputBlockSize() != size / 4)
        {
            fail(size + " getOutputBlockSize() on encryption failed.");
        }

        byte[]  message = Hex.decode("5468697320697320612074657374");

        byte[]  pText = message;
        byte[]  cText = e.processBlock(pText, 0, pText.length);

        e.init(false, pv);

        if (e.getOutputBlockSize() != (size / 8) - 1)
        {
            fail(size + " getOutputBlockSize() on decryption failed.");
        }
        
        pText = e.processBlock(cText, 0, cText.length);

        if (!Arrays.areEqual(message, pText))
        {
            fail(size + " bit test failed");
        }
        
        e.init(true, pu);

        byte[] bytes = new byte[e.getInputBlockSize() + 2];
        
        try
        {
            e.processBlock(bytes, 0, bytes.length);
            
            fail("out of range block not detected");
        }
        catch (DataLengthException ex)
        {
            // expected
        }
        
        try
        {
            bytes[0] = (byte)0xff;
            
            e.processBlock(bytes, 0, bytes.length - 1);
            
            fail("out of range block not detected");
        }
        catch (DataLengthException ex)
        {
            // expected
        }
        
        try
        {
            bytes[0] = (byte)0x7f;

            e.processBlock(bytes, 0, bytes.length - 1);
        }
        catch (DataLengthException ex)
        {
            fail("in range block failed");
        }

        try
        {
            bytes = BigIntegers.asUnsignedByteArray(p);

            e.processBlock(bytes, 0, bytes.length);

            fail("out of range block not detected");
        }
        catch (DataLengthException ex)
        {
            // expected
        }

        try
        {
            bytes = BigIntegers.asUnsignedByteArray(p.subtract(BigInteger.valueOf(1)));

            e.processBlock(bytes, 0, bytes.length);
        }
        catch (DataLengthException ex)
        {
            fail("boundary block rejected");
        }
    }

    private void checkKeySize(
        int privateValueSize,
        ElGamalPrivateKeyParameters priv)
    {
        if (privateValueSize != 0)
        {
            if (priv.getX().bitLength() != privateValueSize)
            {
                fail("limited key check failed for key size " + privateValueSize);
            }
        }
    }

    /**
     * this test is can take quiet a while
     *
     * @param size size of key in bits.
     */
    private void testGeneration(
        int         size)
    {
        ElGamalParametersGenerator       pGen = new ElGamalParametersGenerator();

        pGen.init(size, 10, new SecureRandom());

        ElGamalParameters                elParams = pGen.generateParameters();

        if (elParams.getL() != 0)
        {
            fail("ElGamalParametersGenerator failed to set L to 0 in generated ElGamalParameters");
        }

        ElGamalKeyGenerationParameters   params = new ElGamalKeyGenerationParameters(new SecureRandom(), elParams);

        ElGamalKeyPairGenerator          kpGen = new ElGamalKeyPairGenerator();

        kpGen.init(params);

        //
        // generate first pair
        //
        AsymmetricCipherKeyPair         pair = kpGen.generateKeyPair();

        ElGamalPublicKeyParameters      pu = (ElGamalPublicKeyParameters)pair.getPublic();
        ElGamalPrivateKeyParameters     pv = (ElGamalPrivateKeyParameters)pair.getPrivate();

        ElGamalEngine    e = new ElGamalEngine();

        e.init(true, new ParametersWithRandom(pu, new SecureRandom()));

        byte[]  message = Hex.decode("5468697320697320612074657374");

        byte[]  pText = message;
        byte[]  cText = e.processBlock(pText, 0, pText.length);

        e.init(false, pv);

        pText = e.processBlock(cText, 0, cText.length);

        if (!Arrays.areEqual(message, pText))
        {
            fail("generation test failed");
        }
    }

    private void testInitCheck()
    {
        try
        {
            new ElGamalEngine().processBlock(new byte[]{ 1 }, 0, 1);
            fail("failed initialisation check");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    private void testMaliciousCiphertext()
    {
        // ElGamal decryption raises the first ciphertext component (gamma) to the static private key,
        // so an out-of-range or small-order gamma -- or phi -- must be rejected before the modPow;
        // otherwise a peer can mount a small-subgroup confinement attack against a reused decryption
        // key (the class closed for DHAgreement). The DH analogue is DHTest.testMaliciousMessage.
        ElGamalParameters               dhParams = new ElGamalParameters(p512, g512, 0);
        ElGamalKeyGenerationParameters  params = new ElGamalKeyGenerationParameters(new SecureRandom(), dhParams);
        ElGamalKeyPairGenerator         kpGen = new ElGamalKeyPairGenerator();

        kpGen.init(params);

        ElGamalPrivateKeyParameters     pv = (ElGamalPrivateKeyParameters)kpGen.generateKeyPair().getPrivate();

        ElGamalEngine    e = new ElGamalEngine();

        e.init(false, pv);

        int half = (p512.bitLength() + 7) / 8;

        // weak / out-of-range component values: 0 and 1 (small order / below range), p-1 (order 2)
        // and p (>= range). A well-formed gamma = g^k mod p is always in (1, p-1), so these never
        // arise from a legitimate ciphertext.
        BigInteger[] weak = new BigInteger[]
        {
            BigInteger.valueOf(0),
            BigInteger.valueOf(1),
            p512.subtract(BigInteger.valueOf(1)),
            p512
        };

        // an in-range component (2 lies in [2, p-2]) used to fill the other half, so each case
        // isolates the component under test.
        byte[] goodHalf = BigIntegers.asUnsignedByteArray(half, BigInteger.valueOf(2));

        for (int i = 0; i != weak.length; i++)
        {
            byte[] weakHalf = BigIntegers.asUnsignedByteArray(half, weak[i]);

            // weak gamma (first half), valid phi (second half)
            checkRejected(e, weakHalf, goodHalf, "gamma", weak[i]);
            // valid gamma (first half), weak phi (second half)
            checkRejected(e, goodHalf, weakHalf, "phi", weak[i]);
        }
    }

    private void checkRejected(
        ElGamalEngine e,
        byte[]        firstHalf,
        byte[]        secondHalf,
        String        which,
        BigInteger    value)
    {
        byte[] cText = Arrays.concatenate(firstHalf, secondHalf);

        try
        {
            e.processBlock(cText, 0, cText.length);

            fail("ElGamal accepted weak " + which + " = " + value);
        }
        catch (IllegalArgumentException ex)
        {
            // expected
        }
    }

    public void performTest()
    {
        testEnc(512, 0, g512, p512);
        testEnc(768, 0, g768, p768);
        testEnc(1024, 0, g1024, p1024);

        testEnc(512, 64, g512, p512);
        testEnc(768, 128, g768, p768);

        //
        // generation test.
        //
        testGeneration(258);

        testInitCheck();

        testMaliciousCiphertext();

        testBlindedDecryptionAgrees();
    }

    /**
     * A 513-bit safe prime p = 2q+1 whose generator 2 is a quadratic non-residue, so it has the full
     * order p-1 rather than the order q that ElGamalParametersGenerator picks. Legal ElGamal domain
     * parameters, and the shape OpenPGP keys commonly carry.
     */
    private static final BigInteger FULL_ORDER_P = new BigInteger(
          "182ef717044f5800cc88ede15393b297bb5601295a6fb8a38dd4b7d283cc3b44"
        + "121604fbd4b8b5ad2f77a5fd3fb59606268b3a7330d73032eca97429de6438cb3", 16);
    private static final BigInteger FULL_ORDER_G = BigInteger.valueOf(2);

    /**
     * The sender chooses gamma, which decryption raises to the private key, so that base is blinded
     * with a fresh random value per call. Base blinding does not depend on the group order or on the
     * exponent length, so the parameters here only vary them: a generator of order q, one of the
     * full order p-1 (which ElGamalParametersGenerator never produces), and a short x. The plaintext
     * must be unchanged, and the blinding must draw on the random given to init.
     */
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

    private void testBlindedDecryptionAgrees()
    {
        SecureRandom random = new SecureRandom();

        ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();
        pGen.init(256, 10, random);

        ElGamalParameters[] paramSets = new ElGamalParameters[]
            {
                pGen.generateParameters(),                                  // g of order q
                new ElGamalParameters(FULL_ORDER_P, FULL_ORDER_G),          // g of order p-1
                new ElGamalParameters(p768, g768, 256)                      // short x
            };

        for (int set = 0; set != paramSets.length; set++)
        {
            testBlindedDecryptionAgrees(paramSets[set], random, set);
        }
    }

    private void testBlindedDecryptionAgrees(ElGamalParameters elParams, SecureRandom random, int set)
    {
        for (int key = 0; key != 4; key++)
        {
            ElGamalKeyPairGenerator kpGen = new ElGamalKeyPairGenerator();
            kpGen.init(new ElGamalKeyGenerationParameters(random, elParams));
            AsymmetricCipherKeyPair pair = kpGen.generateKeyPair();

            ElGamalEngine enc = new ElGamalEngine();
            enc.init(true, new ParametersWithRandom(pair.getPublic(), random));

            CountingRandom decRandom = new CountingRandom(random);
            ElGamalEngine dec = new ElGamalEngine();
            dec.init(false, new ParametersWithRandom(pair.getPrivate(), decRandom));

            for (int msg = 0; msg != 8; msg++)
            {
                byte[] plain = new byte[enc.getInputBlockSize()];
                random.nextBytes(plain);
                plain[0] = (byte)(plain[0] & 0x7f | 0x01);      // keep it inside the block

                byte[] cipherText = enc.processBlock(plain, 0, plain.length);

                decRandom.count = 0;
                byte[] first = dec.processBlock(cipherText, 0, cipherText.length);

                // nothing on the decrypt path draws randomness except the blinding value, so this
                // is what fails if the blinding is ever dropped - the plaintext check below cannot
                // tell blinded from unblinded
                if (decRandom.count == 0)
                {
                    fail("decryption did not blind its base (set " + set + ", key " + key + ", msg " + msg + ")");
                }

                if (!Arrays.areEqual(plain, trimLeadingZero(first, plain.length)))
                {
                    fail("blinded decryption recovered the wrong plaintext (set " + set + ", key " + key + ", msg " + msg + ")");
                }

                // the same as the textbook gamma^(p - 1 - x) * phi
                BigInteger p = elParams.getP();
                int half = cipherText.length / 2;
                BigInteger gamma = new BigInteger(1, Arrays.copyOfRange(cipherText, 0, half));
                BigInteger phi = new BigInteger(1, Arrays.copyOfRange(cipherText, half, cipherText.length));
                BigInteger x = ((ElGamalPrivateKeyParameters)pair.getPrivate()).getX();
                BigInteger m = gamma.modPow(p.subtract(BigInteger.valueOf(1)).subtract(x), p).multiply(phi).mod(p);
                if (!m.equals(new BigInteger(1, first)))
                {
                    fail("blinded decryption differs from the textbook one (set " + set + ", key " + key + ", msg " + msg + ")");
                }

                // the blinding value is redrawn per call, so one that did not cancel shows up as
                // decryptions of one ciphertext disagreeing with each other
                for (int rep = 0; rep != 12; rep++)
                {
                    if (!Arrays.areEqual(first, dec.processBlock(cipherText, 0, cipherText.length)))
                    {
                        fail("repeated blinded decryption disagreed (set " + set + ", key " + key + ", msg "
                            + msg + ", rep " + rep + ")");
                    }
                }
            }
        }
    }

    private byte[] trimLeadingZero(byte[] v, int len)
    {
        if (v.length == len)
        {
            return v;
        }

        byte[] rv = new byte[len];

        System.arraycopy(v, v.length - len > 0 ? v.length - len : 0, rv, len - v.length > 0 ? len - v.length : 0,
            v.length < len ? v.length : len);

        return rv;
    }

    public static void main(
        String[]    args)
    {
        runTest(new ElGamalTest());
    }
}
