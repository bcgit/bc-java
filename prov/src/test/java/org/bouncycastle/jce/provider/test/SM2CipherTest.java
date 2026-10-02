package org.bouncycastle.jce.provider.test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.GMCipherSpi;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class SM2CipherTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM2Cipher";
    }

    public void performTest()
        throws Exception
    {
        BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        BigInteger SM2_ECC_H = ECConstants.ONE;
        BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");

        ECParameterSpec aKeyGenParams = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());

        keyPairGenerator.initialize(aKeyGenParams, new TestRandomBigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16));

        KeyPair aKp = keyPairGenerator.generateKeyPair();

        Cipher sm2Engine = Cipher.getInstance("SM2", "BC");

        byte[] m = Strings.toByteArray("encryption standard");

        sm2Engine.init(Cipher.ENCRYPT_MODE, aKp.getPublic(), new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16));

        byte[] enc = sm2Engine.doFinal(m);

        isTrue("enc wrong", Arrays.areEqual(Hex.decode(
            "04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252" +
            "E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01" +
            "B8650053 A89B41C4 18B0C3AA D00D886C 00286467 9C3D7360 C30156FA B7C80A02" +
            "76712DA9 D8094A63 4B766D3A 285E0748 0653426D"), enc));

        sm2Engine.init(Cipher.DECRYPT_MODE, aKp.getPrivate());

        byte[] dec = sm2Engine.doFinal(enc);

        isTrue("dec wrong", Arrays.areEqual(m, dec));
        
        testAlgorithm(aKp, "SM2", GMObjectIdentifiers.sm2encrypt_with_sm3);
        testAlgorithm(aKp, "SM2withSM3", GMObjectIdentifiers.sm2encrypt_with_sm3);

        testMode(aKp);
        testOutputSize(aKp);
        testShortOutputBuffer(aKp);
        testParameterSpecRefused(aKp);
        testBufferErasedByInit(aKp);
        testBufferErasedOnGrowth(aKp);
        testKeySizeOfOtherEcKey(aKp);
        testWrapUnwrap(aKp);
        testAlgorithm(aKp, "SM2withBlake2b", GMObjectIdentifiers.sm2encrypt_with_blake2b512);
        testAlgorithm(aKp, "SM2withBlake2s", GMObjectIdentifiers.sm2encrypt_with_blake2s256);
        testAlgorithm(aKp, "SM2withMD5", GMObjectIdentifiers.sm2encrypt_with_md5);
        testAlgorithm(aKp, "SM2withRIPEMD160", GMObjectIdentifiers.sm2encrypt_with_rmd160);
        testAlgorithm(aKp, "SM2withWhirlpool", GMObjectIdentifiers.sm2encrypt_with_whirlpool);
        testAlgorithm(aKp, "SM2withSHA1", GMObjectIdentifiers.sm2encrypt_with_sha1);
        testAlgorithm(aKp, "SM2withSHA224", GMObjectIdentifiers.sm2encrypt_with_sha224);
        testAlgorithm(aKp, "SM2withSHA256", GMObjectIdentifiers.sm2encrypt_with_sha256);
        testAlgorithm(aKp, "SM2withSHA384", GMObjectIdentifiers.sm2encrypt_with_sha384);
        testAlgorithm(aKp, "SM2withSHA512", GMObjectIdentifiers.sm2encrypt_with_sha512);
    }

    /**
     * Cipher.SM2 takes WRAP_MODE and UNWRAP_MODE at init, as the provider's other asymmetric
     * ciphers do, but wrap() and unwrap() threw UnsupportedOperationException, the default of
     * javax.crypto.CipherSpi, since the class implemented neither. The wrapped form is the
     * encryption of the key's encoding - what a caller that caught the exception, the CMS key
     * transport among them, fell back to - so a key wrapped either way unwraps.
     */
    private void testWrapUnwrap(KeyPair kp)
        throws Exception
    {
        SecretKey aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        String[] names = { "SM2", "SM2/C1C3C2/NoPadding" };
        for (int i = 0; i != names.length; i++)
        {
            Cipher wrapper = Cipher.getInstance(names[i], "BC");
            Cipher unwrapper = Cipher.getInstance(names[i], "BC");
            wrapper.init(Cipher.WRAP_MODE, kp.getPublic());
            unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate());

            byte[] wrapped;
            try
            {
                wrapped = wrapper.wrap(aesKey);
            }
            catch (UnsupportedOperationException e)
            {
                fail(names[i] + " does not implement wrap()");
                return;
            }
            Key unwrapped = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            isTrue(names[i] + " secret key round-trip", unwrapped instanceof SecretKey
                && "AES".equals(unwrapped.getAlgorithm()) && Arrays.areEqual(aesKey.getEncoded(), unwrapped.getEncoded()));

            // the wrapped form is the encryption of the key's encoding, taken in either direction
            Cipher cipher = Cipher.getInstance(names[i], "BC");
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            isTrue(names[i] + " wrapped key decrypts to its encoding",
                Arrays.areEqual(aesKey.getEncoded(), cipher.doFinal(wrapped)));
            cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            isTrue(names[i] + " encrypted encoding unwraps", Arrays.areEqual(aesKey.getEncoded(),
                unwrapper.unwrap(cipher.doFinal(aesKey.getEncoded()), "AES", Cipher.SECRET_KEY).getEncoded()));
        }

        // public and private keys, the private key also by the algorithm its encoding names
        Cipher wrapper = Cipher.getInstance("SM2", "BC");
        Cipher unwrapper = Cipher.getInstance("SM2", "BC");
        wrapper.init(Cipher.WRAP_MODE, kp.getPublic());
        unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        isTrue("SM2 public key round-trip", Arrays.areEqual(kp.getPublic().getEncoded(),
            unwrapper.unwrap(wrapper.wrap(kp.getPublic()), "EC", Cipher.PUBLIC_KEY).getEncoded()));
        byte[] wrappedPrivate = wrapper.wrap(kp.getPrivate());
        isTrue("SM2 private key round-trip", Arrays.areEqual(kp.getPrivate().getEncoded(),
            unwrapper.unwrap(wrappedPrivate, "EC", Cipher.PRIVATE_KEY).getEncoded()));
        isTrue("SM2 private key round-trip, algorithm from the encoding", Arrays.areEqual(kp.getPrivate().getEncoded(),
            unwrapper.unwrap(wrappedPrivate, "", Cipher.PRIVATE_KEY).getEncoded()));

        // a wrapped key that has been altered is a key that cannot be unwrapped
        wrappedPrivate[wrappedPrivate.length - 1] ^= 1;
        try
        {
            unwrapper.unwrap(wrappedPrivate, "EC", Cipher.PRIVATE_KEY);
            fail("SM2 unwrapped an altered wrapped key");
        }
        catch (InvalidKeyException e)
        {
            isTrue("altered wrapped key refusal", "unable to unwrap".equals(e.getMessage()));
        }
    }

    private void testMode(KeyPair kp)
        throws Exception
    {
        byte[] m = Strings.toByteArray("encryption standard");

        Cipher c1c3c2Enc = Cipher.getInstance("SM2/C1C3C2/NoPadding", "BC");
        c1c3c2Enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] enc = c1c3c2Enc.doFinal(m);

        Cipher c1c3c2Dec = Cipher.getInstance("SM2/C1C3C2/NoPadding", "BC");
        c1c3c2Dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        isTrue("C1C3C2 round-trip wrong", Arrays.areEqual(m, c1c3c2Dec.doFinal(enc)));

        Cipher c1c2c3Enc = Cipher.getInstance("SM2/NONE/NoPadding", "BC");
        c1c2c3Enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] enc2 = c1c2c3Enc.doFinal(m);

        Cipher c1c2c3Dec = Cipher.getInstance("SM2/C1C2C3/NoPadding", "BC");
        c1c2c3Dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        isTrue("C1C2C3 round-trip wrong", Arrays.areEqual(m, c1c2c3Dec.doFinal(enc2)));

        Cipher wrongMode = Cipher.getInstance("SM2/C1C2C3/NoPadding", "BC");
        wrongMode.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        try
        {
            wrongMode.doFinal(enc);
            fail("expected decrypt failure across modes");
        }
        catch (Exception expected)
        {
            // expected
        }

        try
        {
            Cipher.getInstance("SM2/CBC/NoPadding", "BC");
            fail("expected NoSuchAlgorithmException for unsupported mode");
        }
        catch (java.security.NoSuchAlgorithmException expected)
        {
            // expected
        }
    }

    /**
     * getOutputSize answers for the next doFinal, which takes the input update() has buffered as
     * well as the length asked about, and has to answer before a Cipher's first doFinal as well as
     * after it. It answered for the length asked about alone, and from an engine that only learns
     * the curve when doFinal initialises it, so on a Cipher that had not run yet it also came out
     * short by the two coordinates of C1: an output array sized from it was too short.
     */
    private void testOutputSize(KeyPair kp)
        throws Exception
    {
        byte[] m = new byte[1000];
        for (int i = 0; i != m.length; i++)
        {
            m[i] = (byte)i;
        }

        int overhead = 0;
        String[] names = { "SM2", "SM2/C1C3C2/NoPadding" };
        for (int t = 0; t != names.length; t++)
        {
            // a Cipher that has not run yet, with the whole message buffered by update()
            Cipher enc = Cipher.getInstance(names[t], "BC");
            enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            int predicted = enc.getOutputSize(m.length);
            enc.update(m, 0, m.length);
            byte[] ct = new byte[enc.getOutputSize(0)];
            int ctLen = enc.doFinal(ct, 0);
            isTrue(names[t] + " encryption output size is exact", predicted == ctLen && ct.length == ctLen);
            overhead = ctLen - m.length;

            // and decryption, with all but the last byte of the ciphertext buffered
            Cipher dec = Cipher.getInstance(names[t], "BC");
            dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            predicted = dec.getOutputSize(ctLen);
            dec.update(ct, 0, ctLen - 1);
            byte[] pt = new byte[dec.getOutputSize(1)];
            int ptLen = dec.doFinal(ct, ctLen - 1, 1, pt, 0);
            isTrue(names[t] + " decryption output size is exact", predicted == m.length && pt.length == m.length);
            isTrue(names[t] + " round trip through arrays sized by getOutputSize",
                ptLen == m.length && Arrays.areEqual(pt, m));
        }

        // the key-wrapping modes take no update() and answer as their directions do
        Cipher wrap = Cipher.getInstance("SM2", "BC");
        wrap.init(Cipher.WRAP_MODE, kp.getPublic());
        isTrue("WRAP_MODE output size is that of encryption", wrap.getOutputSize(16) == 16 + overhead);
        wrap.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        isTrue("UNWRAP_MODE output size is that of decryption", wrap.getOutputSize(16 + overhead) == 16);
    }

    /**
     * doFinal into an array too short for the result copied the result in regardless, so it failed
     * with an ArrayIndexOutOfBoundsException rather than the ShortBufferException the method
     * declares - and only after the operation had consumed the buffered input, so the retry with a
     * larger array that the JCA contract allows found nothing left to process.
     */
    private void testShortOutputBuffer(KeyPair kp)
        throws Exception
    {
        byte[] m = Strings.toByteArray("encryption standard");

        Cipher enc = Cipher.getInstance("SM2", "BC");
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        enc.update(m, 0, m.length);
        int ctSize = enc.getOutputSize(0);
        try
        {
            enc.doFinal(new byte[ctSize - 1], 0);
            fail("SM2 encryption fitted its ciphertext into an array a byte too short");
        }
        catch (ShortBufferException e)
        {
            // expected
        }
        try
        {
            // the room after the offset is what counts, not the array's length
            enc.doFinal(new byte[ctSize], 1);
            fail("SM2 encryption fitted its ciphertext into the room after an offset a byte too short");
        }
        catch (ShortBufferException e)
        {
            // expected
        }
        byte[] ct = new byte[ctSize];
        int ctLen = enc.doFinal(ct, 0);
        isTrue("SM2 encryption retried after ShortBufferException", ctLen == ctSize);

        Cipher dec = Cipher.getInstance("SM2", "BC");
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        dec.update(ct, 0, ctLen);
        try
        {
            dec.doFinal(new byte[m.length - 1], 0);
            fail("SM2 decryption fitted its plaintext into an array a byte too short");
        }
        catch (ShortBufferException e)
        {
            // expected
        }
        byte[] pt = new byte[m.length];
        int ptLen = dec.doFinal(pt, 0);
        isTrue("SM2 decryption retried after ShortBufferException recovers the message",
            ptLen == m.length && Arrays.areEqual(pt, m));
    }

    /**
     * The cipher takes nothing at init - its mode and digest come from the transformation - but it
     * accepted any AlgorithmParameterSpec and ignored it, so whatever a caller believed it was
     * applying, the user ID of the SM2ParameterSpec the SM2 signature takes, say, or an IV, was
     * silently dropped.
     */
    private void testParameterSpecRefused(KeyPair kp)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("SM2", "BC");
        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic(),
                new SM2ParameterSpec(Strings.toByteArray("ALICE123@YAHOO.COM")));
            fail("SM2 encryption accepted an AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("SM2 encryption's refusal names the spec",
                "SM2 cipher takes no AlgorithmParameterSpec: org.bouncycastle.jcajce.spec.SM2ParameterSpec"
                    .equals(e.getMessage()));
        }
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate(), new IvParameterSpec(new byte[16]));
            fail("SM2 decryption accepted an AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("SM2 decryption's refusal names the spec",
                "SM2 cipher takes no AlgorithmParameterSpec: javax.crypto.spec.IvParameterSpec".equals(e.getMessage()));
        }

        // no spec at all is what the cipher takes
        byte[] m = Strings.toByteArray("encryption standard");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic(), (AlgorithmParameterSpec)null);
        byte[] ct = cipher.doFinal(m);
        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate(), (AlgorithmParameterSpec)null);
        isTrue("SM2 round trip with a null AlgorithmParameterSpec", Arrays.areEqual(m, cipher.doFinal(ct)));
    }

    /**
     * Cipher.SM2 buffers its input until doFinal, and on encryption that input is the plaintext.
     * doFinal zeroes the buffer, but a new init only rewound it, so the input of an operation
     * abandoned for a new init stayed in the backing array. Every init now zeroes it, including one
     * that is refused, which ends the operation in progress just the same. javax.crypto.Cipher does
     * not hand out its SPI, so the SPI is driven directly.
     */
    private void testBufferErasedByInit(KeyPair kp)
        throws Exception
    {
        GMCipherSpi spi = new GMCipherSpi.SM2();
        Field field = GMCipherSpi.class.getDeclaredField("buffer");
        field.setAccessible(true);
        Object buffer = field.get(spi);
        Method getBuf = buffer.getClass().getDeclaredMethod("getBuf", new Class[0]);
        getBuf.setAccessible(true);

        byte[] m = Strings.toByteArray("encryption standard");
        SecureRandom random = new SecureRandom();

        spi.engineInit(Cipher.ENCRYPT_MODE, kp.getPublic(), (AlgorithmParameterSpec)null, random);
        spi.engineUpdate(m, 0, m.length);
        isTrue("the plaintext is buffered",
            Arrays.areEqual(m, Arrays.copyOfRange((byte[])getBuf.invoke(buffer, new Object[0]), 0, m.length)));
        spi.engineInit(Cipher.ENCRYPT_MODE, kp.getPublic(), (AlgorithmParameterSpec)null, random);
        isTrue("pending plaintext is zeroed by a new init", isZeroed(getBuf, buffer));

        // an init refused for its key
        spi.engineUpdate(m, 0, m.length);
        try
        {
            spi.engineInit(Cipher.ENCRYPT_MODE, kp.getPrivate(), (AlgorithmParameterSpec)null, random);
            fail("SM2 encryption accepted a private key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
        isTrue("pending plaintext is zeroed by an init refused for its key", isZeroed(getBuf, buffer));

        // and one refused for its AlgorithmParameters, before the init proper is reached
        spi.engineInit(Cipher.ENCRYPT_MODE, kp.getPublic(), (AlgorithmParameterSpec)null, random);
        spi.engineUpdate(m, 0, m.length);
        try
        {
            spi.engineInit(Cipher.ENCRYPT_MODE, kp.getPublic(), AlgorithmParameters.getInstance("AES", "BC"), random);
            fail("SM2 encryption accepted AlgorithmParameters");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }
        isTrue("pending plaintext is zeroed by an init refused for its AlgorithmParameters", isZeroed(getBuf, buffer));
    }

    /**
     * The buffer grows by copying into a larger array; the array it replaces held the input written
     * so far - on encryption, the plaintext - and is zeroed rather than dropped as it stands, where
     * no later erase could reach it.
     */
    private void testBufferErasedOnGrowth(KeyPair kp)
        throws Exception
    {
        GMCipherSpi spi = new GMCipherSpi.SM2();
        Field field = GMCipherSpi.class.getDeclaredField("buffer");
        field.setAccessible(true);
        Object buffer = field.get(spi);
        Method getBuf = buffer.getClass().getDeclaredMethod("getBuf", new Class[0]);
        getBuf.setAccessible(true);

        byte[] m = new byte[20];
        Arrays.fill(m, (byte)0x5A);
        spi.engineInit(Cipher.ENCRYPT_MODE, kp.getPublic(), (AlgorithmParameterSpec)null, new SecureRandom());
        spi.engineUpdate(m, 0, m.length);
        byte[] before = (byte[])getBuf.invoke(buffer, new Object[0]);
        for (int i = 0; i != 8; i++)
        {
            spi.engineUpdate(m, 0, m.length);
        }
        byte[] after = (byte[])getBuf.invoke(buffer, new Object[0]);
        isTrue("the buffer grew", after != before && after.length >= 9 * m.length);
        isTrue("the array the buffer grew out of is zeroed", Arrays.areAllZeroes(before, 0, before.length));
        for (int i = 0; i != 9 * m.length; i++)
        {
            isTrue("the grown buffer holds what was written", after[i] == 0x5A);
        }

        // and single-byte writes, as engineUpdate never makes but the stream offers
        java.lang.reflect.Constructor create = buffer.getClass().getDeclaredConstructor(new Class[0]);
        create.setAccessible(true);
        Object stream = create.newInstance(new Object[0]);
        Method write = stream.getClass().getDeclaredMethod("write", new Class[]{ int.class });
        write.setAccessible(true);
        write.invoke(stream, new Object[]{ new Integer(0x5A) });
        before = (byte[])getBuf.invoke(stream, new Object[0]);
        for (int i = 1; i <= before.length; i++)
        {
            write.invoke(stream, new Object[]{ new Integer(0x5A) });
        }
        isTrue("the array a single-byte write grew out of is zeroed", Arrays.areAllZeroes(before, 0, before.length));
    }

    /**
     * Cipher consults getKeySize under a restricted crypto policy. It answered only for BC's own EC
     * keys, throwing IllegalArgumentException for any other EC key init accepts, and so for any
     * other key at all; the size is now taken from any such key, and init refuses the rest.
     */
    private void testKeySizeOfOtherEcKey(KeyPair kp)
        throws Exception
    {
        GMCipherSpi spi = new GMCipherSpi.SM2();
        final byte[] spki = kp.getPublic().getEncoded();
        final byte[] pkcs8 = kp.getPrivate().getEncoded();
        Key otherPublic = new java.security.PublicKey()
        {
            public String getAlgorithm()
            {
                return "EC";
            }

            public String getFormat()
            {
                return "X.509";
            }

            public byte[] getEncoded()
            {
                return Arrays.clone(spki);
            }
        };
        Key otherPrivate = new java.security.PrivateKey()
        {
            public String getAlgorithm()
            {
                return "EC";
            }

            public String getFormat()
            {
                return "PKCS#8";
            }

            public byte[] getEncoded()
            {
                return Arrays.clone(pkcs8);
            }
        };
        isTrue("the key size of a BC public key", spi.engineGetKeySize(kp.getPublic()) == 256);
        isTrue("the key size of another public EC key", spi.engineGetKeySize(otherPublic) == 256);
        isTrue("the key size of another private EC key", spi.engineGetKeySize(otherPrivate) == 256);
        // a key that is not an EC key is answered as BaseCipherSpi answers it, and refused by init
        Key aes = new SecretKeySpec(new byte[16], "AES");
        isTrue("the key size of a key that is not an EC key", spi.engineGetKeySize(aes) == 16);
        try
        {
            spi.engineInit(Cipher.ENCRYPT_MODE, aes, (AlgorithmParameterSpec)null, new SecureRandom());
            fail("SM2 encryption accepted an AES key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
    }

    private static boolean isZeroed(Method getBuf, Object buffer)
        throws Exception
    {
        byte[] buf = (byte[])getBuf.invoke(buffer, new Object[0]);
        return Arrays.areAllZeroes(buf, 0, buf.length);
    }

    private void testAlgorithm(KeyPair kp, String name, ASN1ObjectIdentifier oid)
        throws Exception
    {
        Cipher sm2Engine1 = Cipher.getInstance(name, "BC");
        Cipher sm2Engine2 = Cipher.getInstance(oid.getId(), "BC");
        
        byte[] m = Strings.toByteArray("encryption standard");

        sm2Engine1.init(Cipher.ENCRYPT_MODE, kp.getPublic(), new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16));

        byte[] enc = sm2Engine1.doFinal(m);

        isTrue(enc.length == sm2Engine1.getOutputSize(m.length));

        sm2Engine2.init(Cipher.DECRYPT_MODE, kp.getPrivate());

        byte[] dec = sm2Engine2.doFinal(enc);

        isTrue("dec wrong", Arrays.areEqual(m, dec));
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SM2CipherTest());
    }
}
