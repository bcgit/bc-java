package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.SecureRandomProvider;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Tests of the SM9 public-key encryption engine (GM/T 0044.4-2016) at the lightweight layer: the
 * GM/T 0044.5 known answers for both data-encapsulation methods, round trips in both modes, and the
 * engine's refusal of what it cannot encrypt or decrypt.
 */
public class SM9EngineTest
    extends SimpleTest
{
    // the GM/T 0044.5-2016 Annex D master key ke, and a one-block SM4-mode C1 || C3 || C2 of "one block" to
    // "Bob" under it with the annex's r: stored, as the SM4 mode refuses to encrypt messages under 16 bytes
    private static final BigInteger ANNEX_D_KE =
        new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
    private static final byte[] ONE_BLOCK_SM4 = Hex.decode(
        "2445471164490618E1EE20528FF1D545B0F14C8BCAA44544F03DAB5DAC07D8FF"
            + "42FFCA97D57CDDC05EA405F2E586FEB3A6930715532B8000759F13059ED59AC0"
            + "059C700E0E8FEE2801B3EEA529A39390C9138881914C3CAD9E1331EA9E430E9F"
            + "195527A7B90D2A8CE59D01C20EC36E06");

    public String getName()
    {
        return "SM9Engine";
    }

    public void performTest()
        throws Exception
    {
        SM9EncMasterKeyPairGenerator kpGen = new SM9EncMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), 256));
        AsymmetricCipherKeyPair master = kpGen.generateKeyPair();
        byte[] identity = Strings.toByteArray("Bob");
        SM9EncPublicKeyParameters bobPublic =
            ((SM9EncMasterPublicKeyParameters)master.getPublic()).getUserPublicKey(identity);
        SM9EncPrivateKeyParameters bobKey =
            ((SM9EncMasterPrivateKeyParameters)master.getPrivate()).generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);

        // both methods round-trip, the stream method at the lengths either side of 16
        int[] streamLengths = { 1, 15, 17, 32 };
        for (int i = 0; i != streamLengths.length; i++)
        {
            byte[] message = message(streamLengths[i]);
            byte[] ciphertext = encrypt(SM9Engine.Mode.STREAM, bobPublic, message);
            isTrue("SM9 stream-mode C2 is the message length at " + message.length + " bytes",
                ciphertext.length == 96 + message.length);
            isTrue("SM9 stream-mode round-trip at " + message.length + " bytes",
                Arrays.areEqual(message, decrypt(SM9Engine.Mode.STREAM, bobKey, ciphertext)));
        }
        int[] sm4Lengths = { 16, 17, 32 };
        for (int i = 0; i != sm4Lengths.length; i++)
        {
            byte[] message = message(sm4Lengths[i]);
            byte[] ciphertext = encrypt(SM9Engine.Mode.SM4, bobPublic, message);
            isTrue("SM9 SM4-mode C2 is the padded message at " + message.length + " bytes",
                ciphertext.length == 96 + ((message.length / 16) + 1) * 16);
            isTrue("SM9 SM4-mode round-trip at " + message.length + " bytes",
                Arrays.areEqual(message, decrypt(SM9Engine.Mode.SM4, bobKey, ciphertext)));
        }

        // a one-block SM4 ciphertext (a message of 0 to 15 bytes, so |C2| = 16) offered to a
        // stream-mode engine is refused by its length, before the pairing
        SM9EncPrivateKeyParameters annexKey = new SM9EncMasterPrivateKeyParameters(ANNEX_D_KE)
            .generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);
        isTrue("SM9 one-block SM4 ciphertext has a 16-byte C2", ONE_BLOCK_SM4.length == 96 + 16);
        InvalidCipherTextException e = decryptRefused(SM9Engine.Mode.STREAM, annexKey, ONE_BLOCK_SM4,
            "SM9 stream-mode engine decrypted a one-block SM4-mode ciphertext");
        isTrue("SM9 stream-mode 16-byte C2 rejection message",
            "SM9 stream-mode ciphertext has a 16-byte C2".equals(e.getMessage()));

        // and the stream mode will not produce a 16-byte C2 either
        e = encryptRefused(SM9Engine.Mode.STREAM, bobPublic, message(16),
            "SM9 stream-mode engine encrypted a 16-byte message");
        isTrue("SM9 stream-mode 16-byte message rejection message",
            "SM9 stream mode cannot encrypt a 16-byte message".equals(e.getMessage()));

        // nor will the SM4 mode, which is why the ciphertext above is a stored one: no message
        // that pads to one block is encrypted
        int[] oneBlockLengths = { 0, 1, 15 };
        for (int i = 0; i != oneBlockLengths.length; i++)
        {
            e = encryptRefused(SM9Engine.Mode.SM4, bobPublic, message(oneBlockLengths[i]),
                "SM9 SM4-mode engine encrypted a " + oneBlockLengths[i] + "-byte message");
            isTrue("SM9 SM4-mode short message rejection message at " + oneBlockLengths[i] + " bytes",
                "SM9 SM4 mode cannot encrypt a message shorter than 16 bytes".equals(e.getMessage()));
        }

        // and the SM4 mode does not accept a 16-byte C2 either - the stored ciphertext, in its own mode
        e = decryptRefused(SM9Engine.Mode.SM4, annexKey, ONE_BLOCK_SM4,
            "SM9 SM4-mode engine decrypted a ciphertext with a 16-byte C2");
        isTrue("SM9 SM4-mode 16-byte C2 rejection message",
            "SM9 SM4-mode ciphertext has a 16-byte C2".equals(e.getMessage()));

        // a two-block SM4 ciphertext offered to the stream mode, and a 32-byte stream ciphertext offered
        // to the SM4 mode, fail the MAC check
        byte[] twoBlocks = encrypt(SM9Engine.Mode.SM4, bobPublic, message(16));
        isTrue("SM9 two-block SM4 ciphertext has a 32-byte C2", twoBlocks.length == 96 + 32);
        e = decryptRefused(SM9Engine.Mode.STREAM, bobKey, twoBlocks,
            "SM9 stream-mode engine decrypted a two-block SM4-mode ciphertext");
        isTrue("SM9 stream-mode MAC rejection message", "SM9 MAC check failed".equals(e.getMessage()));
        byte[] stream32 = encrypt(SM9Engine.Mode.STREAM, bobPublic, message(32));
        e = decryptRefused(SM9Engine.Mode.SM4, bobKey, stream32,
            "SM9 SM4-mode engine decrypted a 32-byte stream-mode ciphertext");
        isTrue("SM9 SM4-mode MAC rejection message", "SM9 MAC check failed".equals(e.getMessage()));

        checkSizingAndRanges(bobPublic);
        checkRefusedInit(master, identity, bobPublic, bobKey);
        checkOneRefusal();
        checkUnusableSource(bobPublic);
        checkUnusableMasterSource();
        checkC1NotOnCurve(bobKey);
        checkKnownAnswers();
        checkEngineMalformedCiphertext(new SM9EncMasterPrivateKeyParameters(ANNEX_D_KE), identity);

        // 96 bytes is C1 || C3 with an empty C2, which the stream mode refuses
        byte[] noC2 = Arrays.copyOfRange(encrypt(SM9Engine.Mode.STREAM, bobPublic, message(1)), 0, 96);
        e = decryptRefused(SM9Engine.Mode.STREAM, bobKey, noC2,
            "SM9 stream-mode engine decrypted a ciphertext with an empty C2");
        isTrue("SM9 stream-mode empty-C2 rejection message",
            "SM9 stream-mode ciphertext has an empty C2".equals(e.getMessage()));
    }

    /**
     * An init the engine refuses, whatever it is refused for, leaves it uninitialised rather than holding
     * the key of the last init that succeeded.
     */
    private void checkRefusedInit(AsymmetricCipherKeyPair master, byte[] identity,
                                  SM9EncPublicKeyParameters bobPublic, SM9EncPrivateKeyParameters bobKey)
        throws Exception
    {
        SM9EncPublicKeyParameters exchangeRecipient = ((SM9EncMasterPublicKeyParameters)master.getPublic())
            .getUserPublicKey(Strings.toByteArray("Alice"), SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
        SM9EncPrivateKeyParameters exchangeKey =
            ((SM9EncMasterPrivateKeyParameters)master.getPrivate()).generateExchangeKey(identity);
        byte[] msg = message(20);

        SM9Engine encryptor = new SM9Engine(SM9Engine.Mode.STREAM);
        encryptor.init(true, new ParametersWithRandom(bobPublic, CryptoServicesRegistrar.getSecureRandom()));
        refusesInit(encryptor, true, exchangeRecipient, "SM9 engine took a recipient key under HID_EXCHANGE");
        refusesBlock(encryptor, msg, "SM9 engine not initialised for encryption",
            "SM9 engine encrypted after a refused init, to the recipient of the init before it");

        byte[] ciphertext = encrypt(SM9Engine.Mode.STREAM, bobPublic, msg);
        SM9Engine decryptor = new SM9Engine(SM9Engine.Mode.STREAM);
        decryptor.init(false, bobKey);
        refusesInit(decryptor, false, exchangeKey, "SM9 engine took a key-exchange key for decryption");
        refusesBlock(decryptor, ciphertext, "SM9 engine not initialised for decryption",
            "SM9 engine decrypted after a refused init, under the key of the init before it");
        refusesSizing(decryptor, ciphertext.length, "SM9 engine sized an output after a refused init");

        // and one refused on the way to the other direction: a decryption key offered for encryption
        decryptor.init(false, bobKey);
        refusesInit(decryptor, true, bobKey, "SM9 engine took a user private key for encryption");
        refusesBlock(decryptor, ciphertext, "SM9 engine not initialised for encryption",
            "SM9 engine ran after an init refused for the other direction");

        // and one refused in obtaining the default source
        encryptor.init(true, new ParametersWithRandom(bobPublic, CryptoServicesRegistrar.getSecureRandom()));
        try
        {
            CryptoServicesRegistrar.setSecureRandomProvider(new SecureRandomProvider()
            {
                public SecureRandom get()
                {
                    throw new IllegalStateException("no default source");
                }
            });
            encryptor.init(true, bobPublic);
            fail("SM9 engine was initialised with no source to draw from");
        }
        catch (IllegalStateException e)
        {
            isTrue("no default source".equals(e.getMessage()));
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        refusesSizing(encryptor, msg.length, "SM9 engine sized an output after an init refused for want of a source");
        refusesBlock(encryptor, msg, "SM9 engine not initialised for encryption",
            "SM9 engine encrypted after an init refused for want of a source");
    }

    // an init the engine refuses, whose message is not checked: what matters is what the engine does next
    private void refusesInit(SM9Engine engine, boolean forEncryption, CipherParameters params, String failure)
    {
        try
        {
            engine.init(forEncryption, params);
            fail(failure);
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    // processBlock on an engine a refused init has left uninitialised
    private void refusesBlock(SM9Engine engine, byte[] input, String message, String failure)
        throws InvalidCipherTextException
    {
        try
        {
            engine.processBlock(input, 0, input.length);
            fail(failure);
        }
        catch (IllegalStateException e)
        {
            isTrue(message.equals(e.getMessage()));
        }
    }

    // getOutputSize on an engine that is not initialised
    private void refusesSizing(SM9Engine engine, int length, String failure)
    {
        try
        {
            engine.getOutputSize(length);
            fail(failure);
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9 engine not initialised".equals(e.getMessage()));
        }
    }

    /**
     * C1 = (1, 1), not on the curve, is refused as such before it reaches the pairing with the user's key.
     */
    private void checkC1NotOnCurve(SM9EncPrivateKeyParameters bobKey)
        throws Exception
    {
        byte[] c1 = new byte[64];
        c1[31] = 1;
        c1[63] = 1;
        byte[] ciphertext = Arrays.concatenate(c1, new byte[32], message(17));
        InvalidCipherTextException e = decryptRefused(SM9Engine.Mode.STREAM, bobKey, ciphertext,
            "SM9 engine decrypted a ciphertext whose C1 is not on the curve");
        isTrue("invalid SM9 ciphertext point C1".equals(e.getMessage()));
    }

    /**
     * A source that yields nothing usable - only zeros, or only ones - is refused once the draws allowed are
     * used up, rather than hanging or having a fallback stand in for r. These run out after 256 draws, so a
     * draw without a bound fails the test rather than hanging it.
     */
    private void checkUnusableSource(SM9EncPublicKeyParameters bobPublic)
        throws Exception
    {
        byte[] msg = message(20);
        for (int fill = 0x00; fill <= 0xFF; fill += 0xFF)
        {
            byte[] source = new byte[32 * 256];
            Arrays.fill(source, (byte)fill);
            SM9Engine engine = new SM9Engine(SM9Engine.Mode.STREAM);
            engine.init(true, new ParametersWithRandom(bobPublic, new FixedSecureRandom(source)));
            try
            {
                engine.processBlock(msg, 0, msg.length);
                fail("SM9 engine encrypted with a source that yields only 0x" + Integer.toHexString(fill));
            }
            catch (InvalidCipherTextException e)
            {
                isTrue("SM9 encryption could not draw a usable ephemeral".equals(e.getMessage()));
            }
        }
    }

    /**
     * The master key is drawn from [1, N-1] as r is: the first draw in range is taken, and a source that
     * yields nothing usable is refused rather than having a fallback stand in (256 draws, twice those allowed).
     */
    private void checkUnusableMasterSource()
    {
        byte[] ke = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(0x4321));
        byte[] redrawn = Arrays.concatenate(new byte[32], BigIntegers.asUnsignedByteArray(32, SM9Curve.N), ke);
        SM9EncMasterKeyPairGenerator kpGen = new SM9EncMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(new FixedSecureRandom(redrawn), 256));
        isTrue("the encryption master key is the first draw in [1, N-1]", Arrays.areEqual(ke,
            ((SM9EncMasterPrivateKeyParameters)kpGen.generateKeyPair().getPrivate()).getEncoded()));

        for (int fill = 0x00; fill <= 0xFF; fill += 0xFF)
        {
            byte[] source = new byte[32 * 256];
            Arrays.fill(source, (byte)fill);
            kpGen.init(new KeyGenerationParameters(new FixedSecureRandom(source), 256));
            try
            {
                kpGen.generateKeyPair();
                fail("SM9EncMasterKeyPairGenerator drew a key from a source that yields only 0x" + Integer.toHexString(fill));
            }
            catch (IllegalStateException e)
            {
                isTrue("SM9 master key generation could not draw a usable key".equals(e.getMessage()));
            }
        }
    }

    /**
     * Decryption refuses a ciphertext the same way whichever check refuses it. Under this key r = 250 gives
     * an all-zero K1 for a one-byte C2, which GM/T 0044.4 7.2.1 B3 rejects, and r = 251 an ordinary one:
     * with a C3 that is not the MAC both fail the MAC check, and with the MAC r = 251 decrypts while r = 250
     * is still refused, by B3 alone.
     */
    private void checkOneRefusal()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master =
            new SM9EncMasterPrivateKeyParameters(new BigInteger("0123456789abcdef0123456789abcdef", 16));
        byte[] identity = Strings.toByteArray("Bob");
        SM9EncPrivateKeyParameters key = master.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);
        ECPoint qb = master.getPublicKeyParameters().recipientPoint(identity, SM9EncMasterPrivateKeyParameters.HID);
        byte[] c2 = new byte[1];

        int[] rs = { 250, 251 };
        for (int i = 0; i != rs.length; i++)
        {
            ECPoint c1 = qb.multiply(BigInteger.valueOf(rs[i])).normalize();
            byte[] c1b = SM9Curve.g1ToBytes(c1);
            byte[] notTheMac = Arrays.concatenate(c1b, new byte[32], c2);
            InvalidCipherTextException e = decryptRefused(SM9Engine.Mode.STREAM, key, notTheMac,
                "SM9 engine decrypted a ciphertext whose C3 is not the MAC, at r = " + rs[i]);
            isTrue("SM9 decryption refusal message at r = " + rs[i], "SM9 MAC check failed".equals(e.getMessage()));

            byte[] withTheMac = Arrays.concatenate(c1b, macFor(key, identity, c1, c2), c2);
            if (rs[i] == 251)
            {
                isTrue("SM9 one-byte C2 with the MAC decrypts at r = 251",
                    decrypt(SM9Engine.Mode.STREAM, key, withTheMac).length == 1);
                continue;
            }
            e = decryptRefused(SM9Engine.Mode.STREAM, key, withTheMac, "SM9 engine decrypted a ciphertext whose K1 is all zero");
            isTrue("SM9 decryption refusal message for an all-zero K1",
                "SM9 MAC check failed".equals(e.getMessage()));
        }
    }

    /**
     * C3 = MAC(K2, C2) as the recipient derives it (GM/T 0044.4 7.2.1 B3-B5).
     */
    private static byte[] macFor(SM9EncPrivateKeyParameters key, byte[] identity, ECPoint c1, byte[] c2)
    {
        byte[] w = SM9Pairing.toBytes(SM9Pairing.pairing(c1, key.getPrivatePoint()));
        byte[] k = SM9Sm3.kdf(Arrays.concatenate(SM9Curve.g1ToBytes(c1), w, identity), (c2.length + 32) * 8);
        SM3Digest sm3 = new SM3Digest();
        sm3.update(c2, 0, c2.length);
        sm3.update(k, c2.length, 32);
        byte[] c3 = new byte[32];
        sm3.doFinal(c3, 0);
        return c3;
    }

    /**
     * The GM/T 0044.5-2016 Annex D vector for both data-encapsulation methods at the engine itself: with the
     * annex's r it writes the annex's C1 || C3 || C2 and decrypts it to the annex's message, which a round trip
     * cannot establish (SM9CipherTest checks the same values through Cipher.SM9).
     */
    private void checkKnownAnswers()
        throws Exception
    {
        Map v = SM9Vectors.load("sm9_encryption.txt");
        byte hid = (byte)Integer.parseInt((String)v.get("hid"), 16);
        byte[] identity = SM9Vectors.hex(v, "IDB");
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(new BigInteger((String)v.get("ke"), 16));
        SM9EncPublicKeyParameters recipient = master.getPublicKeyParameters().getUserPublicKey(identity, hid);
        SM9EncPrivateKeyParameters key = master.generateUserKey(identity, hid);

        checkKnownAnswer(v, SM9Engine.Mode.STREAM, "modeA", recipient, key);
        checkKnownAnswer(v, SM9Engine.Mode.SM4, "modeB", recipient, key);
    }

    private void checkKnownAnswer(Map v, SM9Engine.Mode mode, String method,
                                  SM9EncPublicKeyParameters recipient, SM9EncPrivateKeyParameters key)
        throws Exception
    {
        byte[] message = SM9Vectors.hex(v, "M");
        byte[] expected = Arrays.concatenate(
            Arrays.concatenate(SM9Vectors.hex(v, "C1_x"), SM9Vectors.hex(v, "C1_y")),
            SM9Vectors.hex(v, method + "_C3"), SM9Vectors.hex(v, method + "_C2"));

        SM9Engine engine = new SM9Engine(mode);
        engine.init(true, new ParametersWithRandom(recipient, new TestRandomBigInteger(256, SM9Vectors.hex(v, "r"))));
        isTrue("SM9Engine GM/T 0044.5 " + method + " ciphertext",
            Arrays.areEqual(expected, engine.processBlock(message, 0, message.length)));
        isTrue("SM9Engine GM/T 0044.5 " + method + " decryption",
            Arrays.areEqual(message, decrypt(mode, key, expected)));
    }

    private static byte[] message(int length)
    {
        byte[] message = new byte[length];
        for (int i = 0; i != length; i++)
        {
            message[i] = (byte)(i + 1);
        }
        return message;
    }

    private static byte[] encrypt(SM9Engine.Mode mode, SM9EncPublicKeyParameters recipient, byte[] message)
        throws InvalidCipherTextException
    {
        SM9Engine engine = new SM9Engine(mode);
        engine.init(true, new ParametersWithRandom(recipient, CryptoServicesRegistrar.getSecureRandom()));
        return engine.processBlock(message, 0, message.length);
    }

    private static byte[] decrypt(SM9Engine.Mode mode, SM9EncPrivateKeyParameters userKey, byte[] ciphertext)
        throws InvalidCipherTextException
    {
        SM9Engine engine = new SM9Engine(mode);
        engine.init(false, userKey);
        return engine.processBlock(ciphertext, 0, ciphertext.length);
    }

    // the exception with which encrypt(...) refuses the message; failure is the test's message if it does not
    private InvalidCipherTextException encryptRefused(SM9Engine.Mode mode, SM9EncPublicKeyParameters recipient,
                                                      byte[] message, String failure)
    {
        try
        {
            encrypt(mode, recipient, message);
            fail(failure);
            return null;
        }
        catch (InvalidCipherTextException e)
        {
            return e;
        }
    }

    // the exception with which decrypt(...) refuses the ciphertext; failure is the test's message if it does not
    private InvalidCipherTextException decryptRefused(SM9Engine.Mode mode, SM9EncPrivateKeyParameters userKey,
                                                      byte[] ciphertext, String failure)
    {
        try
        {
            decrypt(mode, userKey, ciphertext);
            fail(failure);
            return null;
        }
        catch (InvalidCipherTextException e)
        {
            return e;
        }
    }

    /**
     * getOutputSize() refuses before init and past what an int can hold, and processBlock refuses a bad
     * range with the DataLengthException SM2Engine gives.
     */
    private void checkSizingAndRanges(SM9EncPublicKeyParameters recipient)
        throws Exception
    {
        SM9Engine engine = new SM9Engine(SM9Engine.Mode.SM4);
        refusesSizing(engine, 10, "SM9Engine sized output before init");

        engine.init(true, new ParametersWithRandom(recipient, CryptoServicesRegistrar.getSecureRandom()));
        isTrue("SM4-mode output size for 15 bytes", engine.getOutputSize(15) == 96 + 16);
        isTrue("SM4-mode output size for 16 bytes", engine.getOutputSize(16) == 96 + 32);
        try
        {
            engine.getOutputSize(Integer.MAX_VALUE);
            fail("SM9Engine returned an overflowed output size");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        byte[] in = new byte[10];
        int[][] badRanges = { { -1, 5 }, { 0, -1 }, { 6, 5 }, { Integer.MAX_VALUE, 1 } };
        for (int i = 0; i != badRanges.length; i++)
        {
            try
            {
                engine.processBlock(in, badRanges[i][0], badRanges[i][1]);
                fail("SM9Engine accepted the range " + badRanges[i][0] + ", " + badRanges[i][1]);
            }
            catch (DataLengthException e)
            {
                isTrue("input buffer too short".equals(e.getMessage()));
            }
        }
    }

    /**
     * processBlock reports a ciphertext it cannot decrypt only as the InvalidCipherTextException it declares:
     * C1 coordinates at or above q, and an SM4-mode C2 that is empty or not a whole number of blocks, under a
     * valid MAC so that its length is what refuses it.
     */
    private void checkEngineMalformedCiphertext(SM9EncMasterPrivateKeyParameters master, byte[] identity)
    {
        SM9EncPrivateKeyParameters userKey = master.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);

        byte[] outOfField = new byte[64 + 32 + 16];
        Arrays.fill(outOfField, 0, 64, (byte)0xff);
        decryptRefused(SM9Engine.Mode.SM4, userKey, outOfField,
            "SM9Engine decrypted a ciphertext with C1 coordinates at or above q");
        decryptRefused(SM9Engine.Mode.STREAM, userKey, outOfField,
            "SM9Engine decrypted a ciphertext with C1 coordinates at or above q in stream mode");

        decryptRefused(SM9Engine.Mode.SM4, userKey, ciphertextWithValidMac(master, identity, new byte[17]),
            "SM9Engine decrypted a ciphertext with a 17-byte SM4-mode C2");
        decryptRefused(SM9Engine.Mode.SM4, userKey, ciphertextWithValidMac(master, identity, new byte[0]),
            "SM9Engine decrypted a ciphertext with an empty SM4-mode C2");
    }

    /**
     * C1 || C3 || C2 as SM9Engine's SM4-mode encryption forms it, for an arbitrary C2: C1 = [r]Q_B,
     * w = e(P_pub-e, P2)^r, K1 || K2 = KDF(C1 || w || ID, (16 + 32) * 8) and C3 = SM3(C2 || K2).
     */
    private static byte[] ciphertextWithValidMac(SM9EncMasterPrivateKeyParameters master, byte[] identity, byte[] c2)
    {
        SM9EncMasterPublicKeyParameters publicKey = master.getPublicKeyParameters();
        BigInteger r = BigInteger.valueOf(0x5a5a5a5aL);
        byte[] c1 = SM9Curve.g1ToBytes(publicKey.recipientPoint(identity).multiply(r));
        Fp12 w = publicKey.pairingWithP2().pow(r);
        byte[] k = SM9Sm3.kdf(Arrays.concatenate(c1, SM9Pairing.toBytes(w), identity), (16 + 32) * 8);

        SM3Digest sm3 = new SM3Digest();
        sm3.update(c2, 0, c2.length);
        sm3.update(k, 16, 32);
        byte[] c3 = new byte[32];
        sm3.doFinal(c3, 0);
        return Arrays.concatenate(c1, c3, c2);
    }

    public static void main(String[] args)
    {
        runTest(new SM9EngineTest());
    }
}
