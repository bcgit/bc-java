package org.bouncycastle.jce.provider.test;

import java.lang.reflect.Constructor;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.symmetric.util.ChaCha20SpecUtil;
import org.bouncycastle.jcajce.spec.BCChaCha20ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The ChaCha20 cipher started at a given block, through BCChaCha20ParameterSpec and, where the runtime has it,
 * the JDK's ChaCha20ParameterSpec (converted by the reflection copy of ChaCha20SpecUtil here; the jdk1.11 copy
 * has its own test, run against the multi-release jar).
 */
public class BCChaCha20ParameterSpecTest
    extends SimpleTest
{
    // RFC 8439 sec. 2.4.2
    private static final byte[] KEY = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] NONCE = Hex.decode("000000000000004a00000000");
    private static final byte[] PLAINTEXT = Strings.toByteArray(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    private static final byte[] CIPHERTEXT = Hex.decode(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
            + "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
            + "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
            + "5af90bbf74a35be6b40b8eedf2785e42874d");

    // RFC 9001 sec. A.5: ChaCha20 header protection, counter and nonce taken from the sample
    private static final byte[] HP_KEY = Hex.decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    private static final byte[] HP_SAMPLE = Hex.decode("5e5cd55c41f69080575d7999c25a5bfb");
    private static final byte[] HP_MASK = Hex.decode("aefefe7d03");

    public String getName()
    {
        return "BCChaCha20ParameterSpec";
    }

    public void performTest()
        throws Exception
    {
        testSpec();
        testRFC8439Vector();
        testRFC9001HeaderProtection();
        testCounterIsUnsigned();
        testDoFinalReturnsToInitialBlock();
        testRepeatedInit();
        testParameters();
        testOtherCiphersRejectSpec();
        testJdkSpec();
    }

    private void testSpec()
    {
        byte[] nonce = Arrays.clone(NONCE);
        BCChaCha20ParameterSpec spec = new BCChaCha20ParameterSpec(nonce, -1);

        nonce[0] ^= 1;
        isTrue("nonce not copied in", Arrays.areEqual(NONCE, spec.getNonce()));
        spec.getNonce()[0] ^= 1;
        isTrue("nonce not copied out", Arrays.areEqual(NONCE, spec.getNonce()));
        isEquals("counter", -1, spec.getCounter());

        try
        {
            new BCChaCha20ParameterSpec(null, 0);
            fail("null nonce accepted");
        }
        catch (NullPointerException e)
        {
            isEquals("nonce cannot be null", e.getMessage());
        }

        checkBadNonceLength(11);
        checkBadNonceLength(13);
    }

    private void checkBadNonceLength(int length)
    {
        try
        {
            new BCChaCha20ParameterSpec(new byte[length], 0);
            fail(length + " byte nonce accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("nonce must be 12 bytes long", e.getMessage());
        }
    }

    private void testRFC8439Vector()
        throws Exception
    {
        Key key = new SecretKeySpec(KEY, "ChaCha20");
        BCChaCha20ParameterSpec spec = new BCChaCha20ParameterSpec(NONCE, 1);

        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        isTrue("RFC 8439 encryption", Arrays.areEqual(CIPHERTEXT, cipher.doFinal(PLAINTEXT)));

        cipher = Cipher.getInstance("ChaCha7539", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        isTrue("RFC 8439 decryption", Arrays.areEqual(PLAINTEXT, cipher.doFinal(CIPHERTEXT)));
    }

    private void testRFC9001HeaderProtection()
        throws Exception
    {
        int counter = (HP_SAMPLE[0] & 0xff) | (HP_SAMPLE[1] & 0xff) << 8 | (HP_SAMPLE[2] & 0xff) << 16
            | (HP_SAMPLE[3] & 0xff) << 24;
        byte[] nonce = Arrays.copyOfRange(HP_SAMPLE, 4, 16);

        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(HP_KEY, "ChaCha20"),
            new BCChaCha20ParameterSpec(nonce, counter));
        isTrue("RFC 9001 header protection mask", Arrays.areEqual(HP_MASK, cipher.doFinal(new byte[5])));
    }

    // Block c started directly must be the block that follows c - 1 in a sequentially generated key stream. This
    // checks the positioning independently of how it is done, across the whole unsigned range: 16 bytes are taken
    // from block c so the last block, c = 2^32 - 1, is never used up.
    private void testCounterIsUnsigned()
        throws Exception
    {
        int[] counters = new int[]{ 1, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 0xffffffff };

        for (int i = 0; i != counters.length; i++)
        {
            int c = counters[i];

            byte[] sequential = keyStream(c - 1, 64 + 16);
            byte[] direct = keyStream(c, 16);

            isTrue("block " + Long.toHexString(c & 0xFFFFFFFFL) + " mispositioned",
                Arrays.areEqual(Arrays.copyOfRange(sequential, 64, 80), direct));
        }
    }

    private void testDoFinalReturnsToInitialBlock()
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "ChaCha20"), new BCChaCha20ParameterSpec(NONCE, 1));

        byte[] first = cipher.doFinal(PLAINTEXT);
        byte[] second = cipher.doFinal(PLAINTEXT);
        isTrue("second doFinal did not restart at the initial block", Arrays.areEqual(CIPHERTEXT, second));
        isTrue("first doFinal", Arrays.areEqual(CIPHERTEXT, first));

        // update then doFinal, then the output-buffer doFinal, each from the initial block
        byte[] split = new byte[PLAINTEXT.length];
        int len = cipher.update(PLAINTEXT, 0, 40, split, 0);
        len += cipher.doFinal(PLAINTEXT, 40, PLAINTEXT.length - 40, split, len);
        isEquals("split length", PLAINTEXT.length, len);
        isTrue("update + doFinal", Arrays.areEqual(CIPHERTEXT, split));

        byte[] buffered = new byte[PLAINTEXT.length];
        cipher.doFinal(PLAINTEXT, 0, PLAINTEXT.length, buffered, 0);
        isTrue("output-buffer doFinal did not restart at the initial block", Arrays.areEqual(CIPHERTEXT, buffered));
    }

    // QUIC and DTLS 1.3 re-initialise with the same key, and possibly the same nonce, for every packet.
    private void testRepeatedInit()
        throws Exception
    {
        Key key = new SecretKeySpec(KEY, "ChaCha20");
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");

        for (int i = 0; i != 2; i++)
        {
            cipher.init(Cipher.ENCRYPT_MODE, key, new BCChaCha20ParameterSpec(NONCE, 1));
            isTrue("repeated encrypt init " + i, Arrays.areEqual(CIPHERTEXT, cipher.doFinal(PLAINTEXT)));

            cipher.init(Cipher.DECRYPT_MODE, key, new BCChaCha20ParameterSpec(NONCE, 1));
            isTrue("repeated decrypt init " + i, Arrays.areEqual(PLAINTEXT, cipher.doFinal(CIPHERTEXT)));
        }

        // a later init with an IvParameterSpec starts at block 0 again, and stays there
        byte[] block0 = keyStream(0, 64);

        cipher.init(Cipher.ENCRYPT_MODE, key, new BCChaCha20ParameterSpec(NONCE, 5));
        cipher.doFinal(new byte[64]);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(NONCE));
        isTrue("IvParameterSpec after a counter", Arrays.areEqual(block0, cipher.doFinal(new byte[64])));
        isTrue("IvParameterSpec after a counter, second doFinal", Arrays.areEqual(block0, cipher.doFinal(new byte[64])));
    }

    private void testParameters()
        throws Exception
    {
        Key key = new SecretKeySpec(KEY, "ChaCha20");
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");

        // parameters can only carry the nonce, so there are none for a non-zero counter
        cipher.init(Cipher.ENCRYPT_MODE, key, new BCChaCha20ParameterSpec(NONCE, 1));
        isTrue("parameters returned for a non-zero counter", cipher.getParameters() == null);
        isTrue("IV", Arrays.areEqual(NONCE, cipher.getIV()));

        // counter 0 is what the nonce alone describes
        cipher.init(Cipher.ENCRYPT_MODE, key, new BCChaCha20ParameterSpec(NONCE, 0));
        AlgorithmParameters params = cipher.getParameters();
        isTrue("no parameters for counter 0", params != null);
        IvParameterSpec ivSpec = (IvParameterSpec)params.getParameterSpec(IvParameterSpec.class);
        isTrue("parameters nonce", Arrays.areEqual(NONCE, ivSpec.getIV()));

        byte[] block0 = cipher.doFinal(new byte[64]);
        Cipher other = Cipher.getInstance("ChaCha20", "BC");
        other.init(Cipher.ENCRYPT_MODE, key, params);
        isTrue("parameters round trip", Arrays.areEqual(block0, other.doFinal(new byte[64])));
    }

    private void testOtherCiphersRejectSpec()
        throws Exception
    {
        checkRejected("ChaCha", 32);
        checkRejected("Salsa20", 32);
        checkRejected("XChaCha20", 32);
        checkRejected("ChaCha20-Poly1305", 32);
    }

    private void checkRejected(String algorithm, int keySize)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance(algorithm, "BC");
        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[keySize], algorithm),
                new BCChaCha20ParameterSpec(NONCE, 1));
            fail(algorithm + " accepted a BCChaCha20ParameterSpec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals(algorithm + " message", "unknown parameter type.", e.getMessage());
        }
    }

    // The JDK's ChaCha20ParameterSpec, built reflectively so this compiles for any Java version; on a runtime
    // without it there is nothing to convert.
    private void testJdkSpec()
        throws Exception
    {
        isTrue("null converted", ChaCha20SpecUtil.toBCChaCha20Spec(null) == null);
        isTrue("IvParameterSpec converted", ChaCha20SpecUtil.toBCChaCha20Spec(new IvParameterSpec(NONCE)) == null);

        Class jdkSpecClass;
        try
        {
            jdkSpecClass = Class.forName("javax.crypto.spec.ChaCha20ParameterSpec");
        }
        catch (ClassNotFoundException e)
        {
            return;
        }

        Constructor constructor = jdkSpecClass.getConstructor(new Class[]{ byte[].class, Integer.TYPE });

        AlgorithmParameterSpec jdkSpec = (AlgorithmParameterSpec)constructor.newInstance(
            new Object[]{ NONCE, Integers.valueOf(-2) });
        BCChaCha20ParameterSpec converted = ChaCha20SpecUtil.toBCChaCha20Spec(jdkSpec);
        isTrue("JDK spec not converted", converted != null);
        isTrue("JDK spec nonce", Arrays.areEqual(NONCE, converted.getNonce()));
        isEquals("JDK spec counter", -2, converted.getCounter());

        jdkSpec = (AlgorithmParameterSpec)constructor.newInstance(new Object[]{ NONCE, Integers.valueOf(1) });
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "ChaCha20"), jdkSpec);
        isTrue("RFC 8439 encryption, JDK spec", Arrays.areEqual(CIPHERTEXT, cipher.doFinal(PLAINTEXT)));
        isTrue("RFC 8439 encryption, JDK spec, second doFinal", Arrays.areEqual(CIPHERTEXT, cipher.doFinal(PLAINTEXT)));
    }

    private static byte[] keyStream(int counter, int length)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "ChaCha20"), new BCChaCha20ParameterSpec(NONCE, counter));

        return cipher.doFinal(new byte[length]);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BCChaCha20ParameterSpecTest());
    }
}
