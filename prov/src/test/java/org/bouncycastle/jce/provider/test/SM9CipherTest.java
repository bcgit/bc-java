package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * JCE-level tests for SM9 public-key encryption exposed as {@code Cipher.SM9}.
 */
public class SM9CipherTest
    extends SimpleTest
{
    // C1, C3 and C2 of a one-block SM4-mode ciphertext of the message "one block" to the identity "Bob"
    // under the GM/T 0044.5-2016 Annex D encryption master key, made with the annex's r: stored, as the
    // SM4 mode no longer encrypts a message of fewer than 16 bytes.
    private static final byte[] ONE_BLOCK_C1 = Hex.decode(
        "042445471164490618E1EE20528FF1D545B0F14C8BCAA44544F03DAB5DAC07D8FF"
            + "42FFCA97D57CDDC05EA405F2E586FEB3A6930715532B8000759F13059ED59AC0");
    private static final byte[] ONE_BLOCK_C3 = Hex.decode(
        "059C700E0E8FEE2801B3EEA529A39390C9138881914C3CAD9E1331EA9E430E9F");
    private static final byte[] ONE_BLOCK_C2 = Hex.decode("195527A7B90D2A8CE59D01C20EC36E06");
    private static final String MODE_MISMATCH =
        "SM9 decryption failed: SM9 ciphertext enType does not match the configured mode";

    public String getName()
    {
        return "SM9Cipher";
    }

    public void performTest()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");
        byte[] plaintext = "hello sm9 encryption".getBytes("US-ASCII");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair masterPair = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)masterPair.getPrivate();
        PrivateKey bobKey = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        PublicKey bobPublic = ((SM9EncMasterPublicKey)masterPair.getPublic()).getUserPublicKey(bob);

        isTrue("SM9 enc user private key identity",
            Arrays.areEqual(bob, ((SM9EncUserPrivateKey)bobKey).getIdentity()));
        SM9EncUserPublicKey bobPublicKey = (SM9EncUserPublicKey)bobPublic;
        isTrue("SM9 enc user public key identity", Arrays.areEqual(bob, bobPublicKey.getIdentity()));
        isTrue("SM9 enc user public key master public key",
            Arrays.areEqual(masterPair.getPublic().getEncoded(), bobPublicKey.getMasterPublicKey().getEncoded()));

        checkShortBufferIsRetryable(bobPublic, bobKey, plaintext);
        checkShortBufferCallIsRepeatable(bobPublic, bobKey, plaintext);
        checkOutputOffsetNearIntegerMax(bobPublic, bobKey, plaintext);
        checkOutputSizeCountsBufferedInput(bobPublic, bobKey);
        checkBufferIsErased(bobPublic);
        checkBufferGrowthIsErased(bobPublic);
        checkKeySize(bobPublic, bobKey, masterPair);
        checkModeNames(bobPublic, bobKey, plaintext);
        checkWrapModesUnsupported(bobPublic, bobKey);

        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(masterPair.getPublic().getEncoded()));
        isTrue("SM9 KeyFactory enc master public round-trip",
            Arrays.areEqual(pub2.getEncoded(), masterPair.getPublic().getEncoded()));

        // the KeyFactory refuses an encryption master public key at the point at infinity, which no KGC
        // produces; the message is asserted, as the core twin asserts it, so no unrelated exception passes
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new byte[]{ 0x00 }).getEncoded()));
            fail("SM9 KeyFactory accepted an encryption master public key at infinity");
        }
        catch (InvalidKeySpecException e)
        {
            isTrue("unable to decode SM9 public key: SM9 encryption master public key cannot be the point at infinity"
                .equals(e.getMessage()));
        }

        // a genuine ciphertext of each mode for the checks below; the SM4-mode one is shown to decrypt, so the
        // refusal of it with a tampered C3 comes from the tampering
        byte[] ct = crypt("SM9", Cipher.ENCRYPT_MODE, bobPublic, plaintext);
        isTrue("SM9 Cipher SM4-mode round-trip", Arrays.areEqual(crypt("SM9", Cipher.DECRYPT_MODE, bobKey, ct), plaintext));
        byte[] ctX = crypt("SM9/XOR/NoPadding", Cipher.ENCRYPT_MODE, bobPublic, plaintext);

        // the stream mode refuses an empty message rather than loop retrying (the SM4 mode refuses it as
        // a message of fewer than 16 bytes, below)
        refusal("SM9/XOR/NoPadding", Cipher.ENCRYPT_MODE, bobPublic, new byte[0], "an empty message");

        SM9Cipher parsed = SM9Cipher.getInstance(ct);
        byte[] brokenC3 = Arrays.clone(parsed.getC3());
        brokenC3[0] ^= 1;
        refusal("SM9", Cipher.DECRYPT_MODE, bobKey,
            new SM9Cipher(parsed.getEnType(), parsed.getC1(), brokenC3, parsed.getC2()).getEncoded(), "a tampered C3");

        // the GM/T 0044.5-2016 Annex D master key, rebuilt from its scalar through the KeyFactory /
        // PKCS#8 path, and the key of its identity "Bob"
        Map kat = SM9Vectors.load("sm9_encryption.txt");
        byte[] katScalar = BigIntegers.asUnsignedByteArray(32, new BigInteger((String)kat.get("ke"), 16));
        PrivateKeyInfo katPkcs8 = new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(katScalar));
        SM9EncMasterPrivateKey katMaster = (SM9EncMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(katPkcs8.getEncoded()));
        KeyPair katBobPair = katMaster.generateUserKeyPair(SM9Vectors.hex(kat, "IDB"), SM9EncMasterPrivateKeyParameters.HID);
        PrivateKey annexBobKey = katBobPair.getPrivate();

        // a ciphertext whose enType names a mode other than the Cipher's is refused, and a 16-byte C2
        // in either mode, shown on the stored one-block ciphertext
        isTrue("SM9 one-block SM4 ciphertext has a 16-byte C2", ONE_BLOCK_C2.length == 16);
        byte[] streamTyped = new SM9Cipher(SM9Cipher.EN_TYPE_STREAM,
            ONE_BLOCK_C1, ONE_BLOCK_C3, ONE_BLOCK_C2).getEncoded();
        // the configured mode decides, not the enType, and that check answers ahead of the length check
        isTrue("SM9 enType mismatch rejection message",
            MODE_MISMATCH.equals(refusal("SM9", Cipher.DECRYPT_MODE, annexBobKey, streamTyped, "a stream enType")));
        // a stream-mode Cipher, whose mode that enType agrees with, refuses the 16-byte C2
        isTrue("SM9 stream-mode 16-byte C2 rejection message",
            "SM9 decryption failed: SM9 stream-mode ciphertext has a 16-byte C2".equals(
                refusal("SM9/XOR/NoPadding", Cipher.DECRYPT_MODE, annexBobKey, streamTyped, "a 16-byte C2")));

        // SM9Cipher parses every GM/T 0080-2020 enType, but Cipher.SM9 decrypts only in the mode it was
        // configured for, so the modes it does not implement are refused by the same comparison
        int[] unimplemented = { SM9Cipher.EN_TYPE_SM4_CBC, SM9Cipher.EN_TYPE_SM4_OFB, SM9Cipher.EN_TYPE_SM4_CFB };
        for (int i = 0; i != unimplemented.length; i++)
        {
            byte[] asOther = new SM9Cipher(unimplemented[i],
                parsed.getC1(), parsed.getC3(), parsed.getC2()).getEncoded();
            isTrue(MODE_MISMATCH.equals(refusal("SM9", Cipher.DECRYPT_MODE, bobKey, asOther,
                "the unimplemented enType " + unimplemented[i])));
        }

        // nor does the SM4-mode default decrypt a stream-mode ciphertext carrying the SM4 enType, at
        // the lengths either side of 16
        int[] lengths = { 1, 15, 17, 32 };
        for (int i = 0; i != lengths.length; i++)
        {
            SM9Cipher streamCt = SM9Cipher.getInstance(
                crypt("SM9/XOR/NoPadding", Cipher.ENCRYPT_MODE, bobPublic, new byte[lengths[i]]));
            isTrue("SM9 stream-mode C2 is the message length", streamCt.getC2().length == lengths[i]);
            byte[] asSm4 = new SM9Cipher(SM9Cipher.EN_TYPE_SM4,
                streamCt.getC1(), streamCt.getC3(), streamCt.getC2()).getEncoded();
            refusal("SM9", Cipher.DECRYPT_MODE, bobKey, asSm4, "a stream-mode ciphertext of " + lengths[i] + " bytes");
        }

        // the stream mode will not produce a 16-byte C2, which no stream-mode recipient could decrypt; the
        // lengths either side of 16 round-trip, as does a 16-byte SM4-mode message, whose padded C2 is 32 bytes
        isTrue("SM9 stream-mode 16-byte message rejection message",
            "SM9 encryption failed: SM9 stream mode cannot encrypt a 16-byte message".equals(
                refusal("SM9/XOR/NoPadding", Cipher.ENCRYPT_MODE, bobPublic, new byte[16], "a 16-byte message")));
        for (int i = 0; i != lengths.length; i++)
        {
            byte[] m = new byte[lengths[i]];
            for (int j = 0; j != m.length; j++)
            {
                m[j] = (byte)(j + 1);
            }
            byte[] ctLen = crypt("SM9/XOR/NoPadding", Cipher.ENCRYPT_MODE, bobPublic, m);
            isTrue("SM9 stream-mode C2 is the message length at " + m.length + " bytes",
                SM9Cipher.getInstance(ctLen).getC2().length == m.length);
            isTrue("SM9 Cipher stream-mode round-trip at " + m.length + " bytes",
                Arrays.areEqual(crypt("SM9/XOR/NoPadding", Cipher.DECRYPT_MODE, bobKey, ctLen), m));
        }
        byte[] ct16 = crypt("SM9", Cipher.ENCRYPT_MODE, bobPublic, new byte[16]);
        isTrue("SM9 SM4-mode 16-byte message pads to a 32-byte C2", SM9Cipher.getInstance(ct16).getC2().length == 32);
        isTrue("SM9 Cipher SM4-mode 16-byte round-trip",
            Arrays.areEqual(crypt("SM9", Cipher.DECRYPT_MODE, bobKey, ct16), new byte[16]));

        // the SM4 mode does not produce a 16-byte C2 either: no message that pads to one block is
        // encrypted, the empty one included
        int[] oneBlockLengths = { 0, 1, 15 };
        for (int i = 0; i != oneBlockLengths.length; i++)
        {
            isTrue("SM9 SM4-mode short message rejection message at " + oneBlockLengths[i] + " bytes",
                "SM9 encryption failed: SM9 SM4 mode cannot encrypt a message shorter than 16 bytes".equals(refusal("SM9",
                    Cipher.ENCRYPT_MODE, bobPublic, new byte[oneBlockLengths[i]], "a " + oneBlockLengths[i] + "-byte message")));
        }

        // nor does it accept one: the stored one-block ciphertext, under its own enType
        byte[] sm4Typed = new SM9Cipher(SM9Cipher.EN_TYPE_SM4, ONE_BLOCK_C1, ONE_BLOCK_C3, ONE_BLOCK_C2).getEncoded();
        isTrue("SM9 SM4-mode 16-byte C2 rejection message",
            "SM9 decryption failed: SM9 SM4-mode ciphertext has a 16-byte C2".equals(
                refusal("SM9", Cipher.DECRYPT_MODE, annexBobKey, sm4Typed, "a 16-byte C2")));

        // and neither mode decrypts the other's genuine ciphertext. The message is asserted: this C2 would
        // fail the SM4 length check or the MAC anyway, so only the message shows which check refused it
        String refused = refusal("SM9", Cipher.DECRYPT_MODE, bobKey, ctX, "a stream-mode ciphertext");
        isTrue("the configured-mode check refused a stream ciphertext in SM4 mode: " + refused,
            MODE_MISMATCH.equals(refused));
        refused = refusal("SM9/XOR/NoPadding", Cipher.DECRYPT_MODE, bobKey, ct, "an SM4-mode ciphertext");
        isTrue("the configured-mode check refused an SM4 ciphertext in stream mode: " + refused,
            MODE_MISMATCH.equals(refused));

        checkCanonicalEncoding("SM9", bobPublic, bobKey, plaintext);
        checkCanonicalEncoding("SM9/XOR/NoPadding", bobPublic, bobKey, plaintext);

        // guards: a master public key is not a recipient key, and no spec is accepted
        keyRefusal(Cipher.ENCRYPT_MODE, masterPair.getPublic());
        specRefusal(Cipher.ENCRYPT_MODE, bobPublic, new AlgorithmParameterSpec()
        {
        }, "SM9 encryption accepted an AlgorithmParameterSpec");

        // a key-exchange user key is the wrong kind of key for decryption and is refused at init, as the
        // KEM and key agreement services refuse the wrong kind of key
        PrivateKey bobExchangeKey = masterPriv.generateExchangeKeyPair(bob).getPrivate();
        isTrue("SM9 decryption requires an encryption user key, not a key-exchange key".equals(
            keyRefusal(Cipher.DECRYPT_MODE, bobExchangeKey).getMessage()));

        // decryption takes no spec either, as encryption takes none
        isTrue(("SM9 decryption takes no AlgorithmParameterSpec; decrypt with the recipient's user private key alone")
            .equals(specRefusal(Cipher.DECRYPT_MODE, bobKey, new IvParameterSpec(new byte[16]),
                "SM9 decryption accepted an AlgorithmParameterSpec").getMessage()));

        // a recipient key formed under HID_EXCHANGE is a key-exchange peer's and is refused at init,
        // while a recipient key under any other hid the KGC publishes still round-trips
        isTrue(("SM9 encryption requires an encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)")
            .equals(keyRefusal(Cipher.ENCRYPT_MODE, masterPriv.generateExchangeKeyPair(bob).getPublic()).getMessage()));
        KeyPair bobUnderOtherHid = masterPriv.generateUserKeyPair(bob, (byte)0x04);
        byte[] ctOtherHid = crypt("SM9", Cipher.ENCRYPT_MODE, bobUnderOtherHid.getPublic(), plaintext);
        isTrue("a recipient key under a KGC-chosen hid still round-trips",
            Arrays.areEqual(plaintext, crypt("SM9", Cipher.DECRYPT_MODE, bobUnderOtherHid.getPrivate(), ctOtherHid)));

        // both GM/T 0044.5-2016 Annex D encryption modes through the provider
        checkEncryptionVector(kat, katBobPair, "SM9/XOR/NoPadding", SM9Cipher.EN_TYPE_STREAM, "modeA");
        checkEncryptionVector(kat, katBobPair, "SM9", SM9Cipher.EN_TYPE_SM4, "modeB");

        // SM9 KEM (GM/T 0044.4) through KeyGenerator.SM9-KEM, to the same recipient public key
        KeyGenerator kemGen = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemGen.init(new KEMGenerateSpec(bobPublic, "AES", 128));
        SecretKeyWithEncapsulation kemEnc = (SecretKeyWithEncapsulation)kemGen.generateKey();

        KeyGenerator kemExt = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemExt.init(new KEMExtractSpec(bobKey, kemEnc.getEncapsulation(), "AES", 128));
        SecretKeyWithEncapsulation kemDec = (SecretKeyWithEncapsulation)kemExt.generateKey();
        isTrue("SM9-KEM encapsulate/decapsulate agree on a 128-bit key",
            kemEnc.getEncoded().length == 16 && Arrays.areEqual(kemEnc.getEncoded(), kemDec.getEncoded()));

        // a different recipient identity does not recover the same key
        PrivateKey mallory = masterPriv.generateUserKeyPair("Mallory".getBytes("US-ASCII"), SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        KeyGenerator kemBad = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemBad.init(new KEMExtractSpec(mallory, kemEnc.getEncapsulation(), "AES", 128));
        isTrue("SM9-KEM wrong identity yields a different key",
            !Arrays.areEqual(kemEnc.getEncoded(), ((SecretKeyWithEncapsulation)kemBad.generateKey()).getEncoded()));

        // a truncated encapsulation is refused cleanly. The try covers only the call that should refuse
        // it, and the message is asserted, so that an unrelated IllegalArgumentException cannot pass
        KeyGenerator kemShort = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemShort.init(new KEMExtractSpec(bobKey, new byte[10], "AES", 128));
        try
        {
            kemShort.generateKey();
            fail("SM9-KEM did not reject a truncated encapsulation");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("invalid SM9 KEM encapsulation".equals(e.getMessage()));
        }

        userKeySpecRoundTrip(kf, (SM9EncMasterPublicKey)masterPair.getPublic(), bobKey, bob,
            SM9EncMasterPrivateKeyParameters.HID, plaintext);
    }

    /**
     * Cipher.SM9 buffers its input, on the encrypt path the plaintext, until doFinal, and zeroes the
     * buffer once used and when a new init, a refused one included, drops what was pending. Cipher does
     * not hand out its SPI, so the SPI is driven directly.
     */
    private void checkBufferIsErased(PublicKey recipient)
        throws Exception
    {
        Class spiClass = org.bouncycastle.jcajce.provider.asymmetric.sm9.CipherSpi.class;
        Object spi = spiClass.getConstructor(new Class[0]).newInstance(new Object[0]);
        Method init = declared(spiClass, "engineInit", new Class[]{ int.class, Key.class, SecureRandom.class });
        Method initWithParams = declared(spiClass, "engineInit",
            new Class[]{ int.class, Key.class, AlgorithmParameters.class, SecureRandom.class });
        Method update = declared(spiClass, "engineUpdate", new Class[]{ byte[].class, int.class, int.class });
        Method doFinal = declared(spiClass, "engineDoFinal", new Class[]{ byte[].class, int.class, int.class });
        Field field = spiClass.getDeclaredField("buffer");
        field.setAccessible(true);
        Object buffer = field.get(spi);
        Method getBuf = declared(buffer.getClass(), "getBuf", new Class[0]);

        byte[] plaintext = Hex.decode("0123456789abcdeffedcba98765432100123456789abcdef");
        Object[] encrypt = new Object[]{ Integers.valueOf(Cipher.ENCRYPT_MODE), recipient, new SecureRandom() };
        Object[] data = new Object[]{ plaintext, Integers.valueOf(0), Integers.valueOf(plaintext.length) };

        init.invoke(spi, encrypt);
        update.invoke(spi, data);
        isTrue("the plaintext is buffered", Arrays.areEqual(plaintext,
            Arrays.copyOfRange((byte[])getBuf.invoke(buffer, new Object[0]), 0, plaintext.length)));
        doFinal.invoke(spi, new Object[]{ null, Integers.valueOf(0), Integers.valueOf(0) });
        isTrue("the plaintext is erased once encrypted", isZero((byte[])getBuf.invoke(buffer, new Object[0])));

        update.invoke(spi, data);
        init.invoke(spi, encrypt);
        isTrue("pending plaintext is erased by a new init", isZero((byte[])getBuf.invoke(buffer, new Object[0])));

        init.invoke(spi, encrypt);
        update.invoke(spi, data);
        try
        {
            init.invoke(spi, new Object[]{ Integers.valueOf(Cipher.DECRYPT_MODE), recipient, new SecureRandom() });
            fail("SM9 decryption init accepted a public key");
        }
        catch (InvocationTargetException e)
        {
            isTrue("public key refused for decryption", e.getTargetException() instanceof InvalidKeyException);
        }
        isTrue("pending plaintext is erased by an init refused for its key",
            isZero((byte[])getBuf.invoke(buffer, new Object[0])));

        // AlgorithmParameters are refused before the rest of init is reached
        init.invoke(spi, encrypt);
        update.invoke(spi, data);
        try
        {
            initWithParams.invoke(spi, new Object[]{ Integers.valueOf(Cipher.ENCRYPT_MODE), recipient,
                AlgorithmParameters.getInstance("AES", "BC"), new SecureRandom() });
            fail("SM9 init accepted AlgorithmParameters");
        }
        catch (InvocationTargetException e)
        {
            isTrue("AlgorithmParameters refused", e.getTargetException() instanceof InvalidAlgorithmParameterException);
        }
        isTrue("pending plaintext is erased by an init refused for its AlgorithmParameters",
            isZero((byte[])getBuf.invoke(buffer, new Object[0])));
    }

    /**
     * The buffer grows as update() adds to it, and ByteArrayOutputStream grows by copying its contents
     * into a larger array, so the array a growth replaces, which the erase after doFinal never
     * reaches, is zeroed.
     */
    private void checkBufferGrowthIsErased(PublicKey recipient)
        throws Exception
    {
        Class spiClass = org.bouncycastle.jcajce.provider.asymmetric.sm9.CipherSpi.class;
        Object spi = spiClass.getConstructor(new Class[0]).newInstance(new Object[0]);
        Method init = declared(spiClass, "engineInit", new Class[]{ int.class, Key.class, SecureRandom.class });
        Method update = declared(spiClass, "engineUpdate", new Class[]{ byte[].class, int.class, int.class });
        Field field = spiClass.getDeclaredField("buffer");
        field.setAccessible(true);
        ByteArrayOutputStream buffer = (ByteArrayOutputStream)field.get(spi);
        Method getBuf = declared(buffer.getClass(), "getBuf", new Class[0]);

        byte[] plaintext = new byte[200];
        for (int i = 0; i != plaintext.length; i++)
        {
            plaintext[i] = (byte)(i + 1);
        }
        init.invoke(spi, new Object[]{ Integers.valueOf(Cipher.ENCRYPT_MODE), recipient, new SecureRandom() });

        // 20 bytes fit the initial array, 180 more do not
        update.invoke(spi, new Object[]{ plaintext, Integers.valueOf(0), Integers.valueOf(20) });
        byte[] replaced = (byte[])getBuf.invoke(buffer, new Object[0]);
        update.invoke(spi, new Object[]{ plaintext, Integers.valueOf(20), Integers.valueOf(180) });
        isTrue("the buffer grew", getBuf.invoke(buffer, new Object[0]) != replaced);
        isTrue("the array a growth replaces is zeroed", isZero(replaced));
        isTrue("the plaintext survives the growth", Arrays.areEqual(plaintext, buffer.toByteArray()));

        // and a growth by write(int), which the stream takes as well
        replaced = (byte[])getBuf.invoke(buffer, new Object[0]);
        while (getBuf.invoke(buffer, new Object[0]) == replaced)
        {
            buffer.write(0x5a);
        }
        isTrue("the array a growth by write(int) replaces is zeroed", isZero(replaced));
        isTrue("the plaintext survives a growth by write(int)",
            Arrays.areEqual(plaintext, Arrays.copyOfRange(buffer.toByteArray(), 0, plaintext.length)));
    }

    /**
     * javax.crypto.Cipher asks the SPI for the key's size under a restricted crypto policy: 256, the SM9
     * curve's, or, for a key init would not take, InvalidKeyException as init gives. The policy is fixed
     * for the life of a JVM, so the SPI is asked directly.
     */
    private void checkKeySize(PublicKey recipient, PrivateKey key, KeyPair master)
        throws Exception
    {
        Class spiClass = org.bouncycastle.jcajce.provider.asymmetric.sm9.CipherSpi.class;
        Object spi = spiClass.getConstructor(new Class[0]).newInstance(new Object[0]);
        Method getKeySize = declared(spiClass, "engineGetKeySize", new Class[]{ Key.class });

        Key[] sm9Keys = { recipient, key };
        for (int i = 0; i != sm9Keys.length; i++)
        {
            isTrue("SM9 key size of " + sm9Keys[i].getClass().getName(),
                ((Integer)getKeySize.invoke(spi, new Object[]{ sm9Keys[i] })).intValue() == 256);
        }
        Key[] notTaken = { master.getPublic(), master.getPrivate(), new javax.crypto.spec.SecretKeySpec(new byte[16], "AES") };
        for (int i = 0; i != notTaken.length; i++)
        {
            try
            {
                getKeySize.invoke(spi, new Object[]{ notTaken[i] });
                fail("SM9 cipher sized " + notTaken[i].getClass().getName());
            }
            catch (InvocationTargetException e)
            {
                isTrue("SM9 cipher refuses to size " + notTaken[i].getClass().getName(),
                    e.getTargetException() instanceof InvalidKeyException);
            }
        }
    }

    /**
     * Cipher.SM9 does not wrap or unwrap, and javax.crypto.Cipher.init documents
     * UnsupportedOperationException for a wrap or unwrap mode the CipherSpi does not implement.
     */
    private void checkWrapModesUnsupported(PublicKey recipient, PrivateKey key)
        throws Exception
    {
        int[] modes = { Cipher.WRAP_MODE, Cipher.UNWRAP_MODE };
        Key[] keys = { recipient, key };
        for (int i = 0; i != modes.length; i++)
        {
            try
            {
                Cipher.getInstance("SM9", "BC").init(modes[i], keys[i]);
                fail("SM9 cipher was initialised for opmode " + modes[i]);
            }
            catch (UnsupportedOperationException e)
            {
                isTrue("SM9 cipher refusal of opmode " + modes[i] + ": " + e.getMessage(),
                    "SM9 cipher supports only ENCRYPT_MODE and DECRYPT_MODE".equals(e.getMessage()));
            }
        }
    }

    /**
     * Every mode name the transformation takes reaches the mode it names, "SM4", "ECB", "STREAM" and
     * "KDF" included, which the rest of this test does not use: a mode silently swapped, or the name
     * refused, would otherwise go unnoticed.
     */
    private void checkModeNames(PublicKey recipient, PrivateKey key, byte[] plaintext)
        throws Exception
    {
        String[] sm4 = { "SM9/SM4/NoPadding", "SM9/ECB/NoPadding" };
        String[] stream = { "SM9/XOR/NoPadding", "SM9/STREAM/NoPadding", "SM9/KDF/NoPadding" };
        String[][] names = { sm4, stream };
        int[] enTypes = { SM9Cipher.EN_TYPE_SM4, SM9Cipher.EN_TYPE_STREAM };
        String[] defaults = { "SM9", "SM9/XOR/NoPadding" };
        for (int m = 0; m != names.length; m++)
        {
            for (int i = 0; i != names[m].length; i++)
            {
                byte[] ct = crypt(names[m][i], Cipher.ENCRYPT_MODE, recipient, plaintext);
                isTrue(names[m][i] + " writes its mode's enType", SM9Cipher.getInstance(ct).getEnType() == enTypes[m]);
                isTrue(names[m][i] + " round-trip",
                    Arrays.areEqual(plaintext, crypt(names[m][i], Cipher.DECRYPT_MODE, key, ct)));
                // and it is the same mode as the name the rest of this test uses for it
                isTrue(names[m][i] + " is the mode " + defaults[m] + " names",
                    Arrays.areEqual(plaintext, crypt(defaults[m], Cipher.DECRYPT_MODE, key, ct)));
            }
        }

        // a mode the cipher does not implement is refused by name, never served as another: the
        // GM/T 0080-2020 CBC, OFB and CFB data encapsulations among them
        String[] unsupported = { "SM9/CBC/NoPadding", "SM9/OFB/NoPadding", "SM9/CFB/NoPadding", "SM9/GCM/NoPadding" };
        for (int i = 0; i != unsupported.length; i++)
        {
            try
            {
                Cipher.getInstance(unsupported[i], "BC");
                fail(unsupported[i] + " was taken");
            }
            catch (java.security.NoSuchAlgorithmException e)
            {
                // refused, as it should be
            }
        }
    }

    private static Method declared(Class c, String name, Class[] parameterTypes)
        throws Exception
    {
        Method m = c.getDeclaredMethod(name, parameterTypes);
        m.setAccessible(true);
        return m;
    }

    private static boolean isZero(byte[] b)
    {
        return Arrays.areAllZeroes(b, 0, b.length);
    }

    /**
     * The JCA contract for ShortBufferException is that the call can be retried with a larger buffer,
     * so the Cipher finds the output too short before it consumes the input it has buffered.
     */
    private void checkShortBufferIsRetryable(PublicKey recipient, PrivateKey key, byte[] plaintext)
        throws Exception
    {
        Cipher enc = Cipher.getInstance("SM9", "BC");
        enc.init(Cipher.ENCRYPT_MODE, recipient);
        enc.update(plaintext, 0, plaintext.length);
        refusesShortOutput(enc, null, 0, 0, new byte[8], 0, "SM9 encryption");
        byte[] ct = new byte[enc.getOutputSize(0)];
        int ctLen = enc.doFinal(ct, 0);
        Cipher check = Cipher.getInstance("SM9", "BC");
        check.init(Cipher.DECRYPT_MODE, key);
        isTrue("an SM9 encryption retried after ShortBufferException still encrypts the buffered input",
            Arrays.areEqual(check.doFinal(ct, 0, ctLen), plaintext));

        Cipher dec = Cipher.getInstance("SM9", "BC");
        dec.init(Cipher.DECRYPT_MODE, key);
        dec.update(ct, 0, ctLen);
        refusesShortOutput(dec, null, 0, 0, new byte[2], 0, "SM9 decryption");
        byte[] pt = new byte[plaintext.length];
        int ptLen = dec.doFinal(pt, 0);
        isTrue("an SM9 decryption retried after ShortBufferException recovers the plaintext",
            ptLen == plaintext.length && Arrays.areEqual(pt, plaintext));

        // the transformation's padding is always NoPadding; the SM4 mode's PKCS#7 is part of the data
        // encapsulation, not a padding the caller chooses
        try
        {
            Cipher.getInstance("SM9/SM4/PKCS7Padding", "BC");
            fail("SM9 took a JCA padding it does not apply");
        }
        catch (javax.crypto.NoSuchPaddingException e)
        {
            // expected
        }
    }

    /**
     * The call to repeat after ShortBufferException is the doFinal that threw it, input and all, so only
     * what update() had buffered is kept for it: a repeated encryption encrypts the message once, and a
     * repeated decryption does not see the ciphertext doubled.
     */
    private void checkShortBufferCallIsRepeatable(PublicKey recipient, PrivateKey key, byte[] plaintext)
        throws Exception
    {
        String[] names = { "SM9", "SM9/XOR/NoPadding" };
        for (int i = 0; i != names.length; i++)
        {
            // with nothing buffered ahead of the call, and with its first 5 bytes buffered by update()
            for (int split = 0; split <= 5; split += 5)
            {
                int rest = plaintext.length - split;
                Cipher enc = Cipher.getInstance(names[i], "BC");
                enc.init(Cipher.ENCRYPT_MODE, recipient);
                enc.update(plaintext, 0, split);
                refusesShortOutput(enc, plaintext, split, rest, new byte[8], 0,
                    names[i] + " encryption with " + split + " bytes buffered");
                byte[] ct = new byte[enc.getOutputSize(rest)];
                int ctLen = enc.doFinal(plaintext, split, rest, ct, 0);
                Cipher dec = Cipher.getInstance(names[i], "BC");
                dec.init(Cipher.DECRYPT_MODE, key);
                isTrue(names[i] + " encryption repeated after ShortBufferException encrypts the message once",
                    Arrays.areEqual(dec.doFinal(ct, 0, ctLen), plaintext));

                dec.init(Cipher.DECRYPT_MODE, key);
                dec.update(ct, 0, split);
                refusesShortOutput(dec, ct, split, ctLen - split, new byte[2], 0,
                    names[i] + " decryption with " + split + " bytes buffered");
                byte[] pt = new byte[plaintext.length];
                int ptLen = dec.doFinal(ct, split, ctLen - split, pt, 0);
                isTrue(names[i] + " decryption repeated after ShortBufferException recovers the plaintext",
                    ptLen == plaintext.length && Arrays.areEqual(pt, plaintext));
            }
        }
    }

    /**
     * doFinal's test for an output array too short does not overflow for an output offset near
     * Integer.MAX_VALUE (javax.crypto.Cipher refuses only a negative one): it throws the
     * ShortBufferException the call can be repeated after, keeping the input update() buffered.
     */
    private void checkOutputOffsetNearIntegerMax(PublicKey recipient, PrivateKey key, byte[] plaintext)
        throws Exception
    {
        Cipher enc = Cipher.getInstance("SM9", "BC");
        enc.init(Cipher.ENCRYPT_MODE, recipient);
        enc.update(plaintext, 0, 5);
        refusesShortOutput(enc, plaintext, 5, plaintext.length - 5, new byte[100], Integer.MAX_VALUE, "SM9 encryption");
        byte[] ct = enc.doFinal(plaintext, 5, plaintext.length - 5);

        Cipher dec = Cipher.getInstance("SM9", "BC");
        dec.init(Cipher.DECRYPT_MODE, key);
        dec.update(ct, 0, 5);
        refusesShortOutput(dec, ct, 5, ct.length - 5, new byte[100], Integer.MAX_VALUE - 10, "SM9 decryption");
        isTrue("an SM9 decryption repeated after an output offset near Integer.MAX_VALUE recovers the plaintext",
            Arrays.areEqual(dec.doFinal(ct, 5, ct.length - 5), plaintext));
    }

    // doFinal(input, inputOffset, inputLen, output, outputOffset), or doFinal(output, outputOffset) when
    // input is null, is refused with a ShortBufferException; label names the operation
    private void refusesShortOutput(Cipher cipher, byte[] input, int inputOffset, int inputLen, byte[] output,
                                    int outputOffset, String label)
        throws Exception
    {
        try
        {
            if (input == null)
            {
                cipher.doFinal(output, outputOffset);
            }
            else
            {
                cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
            }
            fail(label + " fitted its result into " + output.length + " bytes at offset " + outputOffset);
        }
        catch (javax.crypto.ShortBufferException e)
        {
            // the call can be repeated with a larger output array
        }
    }

    /**
     * getOutputSize(n) answers for the next update or doFinal, so it counts the input update() has
     * already buffered, in both directions and both modes.
     */
    private void checkOutputSizeCountsBufferedInput(PublicKey recipient, PrivateKey key)
        throws Exception
    {
        byte[] message = new byte[1000];
        for (int i = 0; i != message.length; i++)
        {
            message[i] = (byte)i;
        }
        String[] transformations = { "SM9", "SM9/XOR/NoPadding" };
        for (int t = 0; t != transformations.length; t++)
        {
            Cipher enc = Cipher.getInstance(transformations[t], "BC");
            enc.init(Cipher.ENCRYPT_MODE, recipient);
            enc.update(message, 0, message.length);
            byte[] ct = new byte[enc.getOutputSize(0)];
            int ctLen = enc.doFinal(ct, 0);

            // and decryption, with all but the last byte of the ciphertext buffered
            Cipher dec = Cipher.getInstance(transformations[t], "BC");
            dec.init(Cipher.DECRYPT_MODE, key);
            dec.update(ct, 0, ctLen - 1);
            byte[] pt = new byte[dec.getOutputSize(1)];
            int ptLen = dec.doFinal(ct, ctLen - 1, 1, pt, 0);
            isTrue(transformations[t] + " round-trips through arrays sized by getOutputSize after update()",
                ptLen == message.length && Arrays.areEqual(Arrays.copyOfRange(pt, 0, ptLen), message));
        }
    }

    /**
     * A user's encryption private key does not carry the master public key, identity or hid decryption
     * needs, so it is rebuilt through an SM9EncUserPrivateKeySpec that supplies them - with only the
     * published master public key, never the master private key.
     */
    private void userKeySpecRoundTrip(KeyFactory kf, SM9EncMasterPublicKey masterPub, PrivateKey bobKey,
                                      byte[] identity, byte hid, byte[] plaintext)
        throws Exception
    {
        byte[] stored = bobKey.getEncoded();

        PrivateKey rebuilt = kf.generatePrivate(new SM9EncUserPrivateKeySpec(stored, masterPub, identity, hid));
        isTrue("SM9 user private key spec round-trip", Arrays.areEqual(stored, rebuilt.getEncoded()));
        isTrue("SM9 spec-rebuilt user key identity",
            Arrays.areEqual(identity, ((SM9EncUserPrivateKey)rebuilt).getIdentity()));

        byte[] ct = crypt("SM9", Cipher.ENCRYPT_MODE, masterPub.getUserPublicKey(identity), plaintext);
        isTrue("SM9 decryption with a spec-rebuilt user key round-trips",
            Arrays.areEqual(crypt("SM9", Cipher.DECRYPT_MODE, rebuilt, ct), plaintext));

        // the factory hands the same spec back for a user key
        SM9EncUserPrivateKeySpec roundTripSpec = (SM9EncUserPrivateKeySpec)kf.getKeySpec(
            bobKey, SM9EncUserPrivateKeySpec.class);
        isTrue("SM9 getKeySpec round-trip encoding", Arrays.areEqual(stored, roundTripSpec.getEncoded()));
        isTrue("SM9 getKeySpec round-trip master public key",
            Arrays.areEqual(masterPub.getEncoded(), roundTripSpec.getMasterPublicKey().getEncoded()));
        isTrue("SM9 getKeySpec round-trip identity", Arrays.areEqual(identity, roundTripSpec.getIdentity()));
        isTrue("SM9 getKeySpec round-trip hid", hid == roundTripSpec.getHid());
    }

    /**
     * A ciphertext is decrypted only in the DER encoding encryption produces. Two variants parse to the
     * same C1 || C3 || C2 the engine is handed - C1's prefix byte is not part of that - and three move a
     * byte across a field boundary, which the SM9Cipher type refuses to parse, as C1 and C3 have fixed
     * sizes. Each variant is refused.
     */
    private void checkCanonicalEncoding(String transformation, PublicKey recipient, PrivateKey key, byte[] plaintext)
        throws Exception
    {
        byte[] ct = crypt(transformation, Cipher.ENCRYPT_MODE, recipient, plaintext);
        SM9Cipher parsed = SM9Cipher.getInstance(ct);
        int enType = parsed.getEnType();
        byte[] c1 = parsed.getC1();
        byte[] c3 = parsed.getC3();
        byte[] c2 = parsed.getC2();

        byte[] c1Prefix = Arrays.clone(c1);
        c1Prefix[0] = 0x00;
        rejectsEncoding(transformation, key, ct, new SM9Cipher(enType, c1Prefix, c3, c2).getEncoded(),
            "a C1 prefix byte other than 0x04");
        rejectsEncoding(transformation, key, ct, nonMinimalLength(ct), "a non-minimal length");
        rejectsMalformed(transformation, key, cipherEncoding(enType, Arrays.append(c1, (byte)0x00), c3, c2),
            "a byte past the end of C1");
        rejectsMalformed(transformation, key,
            cipherEncoding(enType, c1, Arrays.copyOfRange(c3, 0, 31), Arrays.prepend(c2, c3[31])),
            "C3 one byte short with C2 carrying its last byte");
        rejectsMalformed(transformation, key,
            cipherEncoding(enType, c1, Arrays.append(c3, c2[0]), Arrays.copyOfRange(c2, 1, c2.length)),
            "C3 one byte long carrying the first byte of C2");

        isTrue(transformation + " canonical ciphertext decrypts",
            Arrays.areEqual(crypt(transformation, Cipher.DECRYPT_MODE, key, ct), plaintext));
    }

    private void rejectsEncoding(String transformation, PrivateKey key, byte[] ct, byte[] variant, String label)
        throws Exception
    {
        isTrue(transformation + " " + label + " parses to the same C1 || C3 || C2",
            Arrays.areEqual(engineInput(ct), engineInput(variant)));
        refusal(transformation, Cipher.DECRYPT_MODE, key, variant, "a ciphertext with " + label);
    }

    private void rejectsMalformed(String transformation, PrivateKey key, byte[] variant, String label)
        throws Exception
    {
        try
        {
            SM9Cipher.getInstance(variant);
            fail(transformation + " SM9Cipher parsed a ciphertext with " + label);
        }
        catch (IllegalArgumentException e)
        {
            // C1 and C3 have fixed sizes
        }
        refusal(transformation, Cipher.DECRYPT_MODE, key, variant, "a ciphertext with " + label);
    }

    // Cipher.getInstance(transformation, "BC"), initialised for opmode with key, applied to input
    private static byte[] crypt(String transformation, int opmode, Key key, byte[] input)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance(transformation, "BC");
        cipher.init(opmode, key);
        return cipher.doFinal(input);
    }

    // the message of the BadPaddingException the crypt() call is refused with; label names the input
    private String refusal(String transformation, int opmode, Key key, byte[] input, String label)
        throws Exception
    {
        try
        {
            crypt(transformation, opmode, key, input);
        }
        catch (BadPaddingException e)
        {
            return e.getMessage();
        }
        fail(transformation + (opmode == Cipher.ENCRYPT_MODE ? " encrypted " : " decrypted ") + label);
        return null;
    }

    // the InvalidKeyException Cipher.SM9 refuses init(opmode, key) with
    private InvalidKeyException keyRefusal(int opmode, Key key)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("SM9", "BC");
        try
        {
            cipher.init(opmode, key);
        }
        catch (InvalidKeyException e)
        {
            return e;
        }
        fail("SM9 cipher took a " + key.getClass().getName() + " for opmode " + opmode);
        return null;
    }

    // the InvalidAlgorithmParameterException Cipher.SM9 refuses init(opmode, key, spec) with; label is the
    // failure reported if it does not
    private InvalidAlgorithmParameterException specRefusal(int opmode, Key key, AlgorithmParameterSpec spec, String label)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("SM9", "BC");
        try
        {
            cipher.init(opmode, key, spec);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            return e;
        }
        fail(label);
        return null;
    }

    // an SM9Cipher encoding written field by field, so that it can carry sizes the type refuses
    private static byte[] cipherEncoding(int enType, byte[] c1, byte[] c3, byte[] c2)
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(new ASN1Integer(enType));
        v.add(new DERBitString(c1));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        return new DERSequence(v).getEncoded();
    }

    private static byte[] engineInput(byte[] ciphertext)
    {
        SM9Cipher c = SM9Cipher.getInstance(ciphertext);
        return Arrays.concatenate(Arrays.copyOfRange(c.getC1(), 1, 65), c.getC3(), c.getC2());
    }

    // the same encoding with the outer SEQUENCE length written in one more octet than DER allows
    private static byte[] nonMinimalLength(byte[] der)
    {
        if ((der[1] & 0x80) == 0)
        {
            return Arrays.concatenate(new byte[]{ der[0], (byte)0x81 }, Arrays.copyOfRange(der, 1, der.length));
        }
        return Arrays.concatenate(new byte[]{ der[0], (byte)(0x81 + (der[1] & 0x7f)), 0x00 },
            Arrays.copyOfRange(der, 2, der.length));
    }

    private void checkEncryptionVector(Map kat, KeyPair recipient, String transformation,
                                       int enType, String fieldPrefix)
        throws Exception
    {
        byte[] c1 = Arrays.concatenate(new byte[]{0x04}, SM9Vectors.hex(kat, "C1_x"), SM9Vectors.hex(kat, "C1_y"));
        byte[] expectedC2 = SM9Vectors.hex(kat, fieldPrefix + "_C2");
        byte[] expectedC3 = SM9Vectors.hex(kat, fieldPrefix + "_C3");
        byte[] message = SM9Vectors.hex(kat, "M");

        Cipher katEnc = Cipher.getInstance(transformation, "BC");
        katEnc.init(Cipher.ENCRYPT_MODE, recipient.getPublic(),
            new TestRandomBigInteger(256, SM9Vectors.hex(kat, "r")));
        SM9Cipher actual = SM9Cipher.getInstance(katEnc.doFinal(message));
        isTrue(fieldPrefix + " GM/T 0044.5 enType", actual.getEnType() == enType);
        isTrue(fieldPrefix + " GM/T 0044.5 C1", Arrays.areEqual(actual.getC1(), c1));
        isTrue(fieldPrefix + " GM/T 0044.5 C2", Arrays.areEqual(actual.getC2(), expectedC2));
        isTrue(fieldPrefix + " GM/T 0044.5 C3", Arrays.areEqual(actual.getC3(), expectedC3));

        byte[] officialCiphertext = new SM9Cipher(enType, c1, expectedC3, expectedC2).getEncoded();
        isTrue(fieldPrefix + " GM/T 0044.5 decrypt",
            Arrays.areEqual(crypt(transformation, Cipher.DECRYPT_MODE, recipient.getPrivate(), officialCiphertext), message));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new SM9CipherTest());
    }
}
