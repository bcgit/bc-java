package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.PreCompInfo;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Known-answer test for the SM9 key encapsulation mechanism (GM/T 0044.4-2016)
 * against the GM/T 0044.5-2016 Part 5, Annex C vector (crypto/sm9/sm9_kem.txt):
 * the encapsulation C and shared key K are reproduced byte-for-byte, and the
 * decapsulation recovers K.
 */
public class SM9KEMTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9KEM";
    }

    public void performTest()
        throws Exception
    {
        Map v = SM9Vectors.load("sm9_kem.txt");
        BigInteger ke = new BigInteger((String)v.get("ke"), 16);
        byte[] identity = SM9Vectors.hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));

        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(ke);
        SM9EncPublicKeyParameters recipient = master.getPublicKeyParameters().getUserPublicKey(identity);

        // the master public key and the KGC-derived user key the standard prints
        // alongside the encapsulation (P_pub-e = [ke]P1 in G1, de_B = [t2]P2 in G2)
        isTrue("SM9 KEM master public key Ppub-e", Arrays.areEqual(
            master.getPublicKeyParameters().getEncoded(),
            Arrays.concatenate(new byte[]{0x04}, SM9Vectors.hex(v, "Ppube_x"), SM9Vectors.hex(v, "Ppube_y"))));
        isTrue("SM9 KEM user key deB", Arrays.areEqual(
            master.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID).getPrivatePoint().getEncoded(),
            SM9Vectors.g2(v, "deB_x_hi", "deB_x_lo", "deB_y_hi", "deB_y_lo")));

        // P_pub-e = [ke]P1 is never the point at infinity for ke in [1, N-1], so the one-octet encoding of
        // infinity is refused when the key is decoded
        try
        {
            SM9EncMasterPublicKeyParameters.fromEncoded(new byte[]{ 0x00 });
            fail("SM9 encryption master public key decoded at infinity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 encryption master public key cannot be the point at infinity".equals(e.getMessage()));
        }

        checkDegenerateRecipientPoint();
        checkMultiplyRecipientPoint();
        checkMalformedEncapsulation(master, identity, klen);
        checkUnusableSource(recipient, klen);

        // e(P_pub-e, P2) is the same for every operation under a master public key: the key computes it
        // once and hands back what it computed
        SM9EncMasterPublicKeyParameters masterPublic = master.getPublicKeyParameters();
        Fp12 g = masterPublic.pairingWithP2();
        isTrue("the fixed pairing is computed once", g == masterPublic.pairingWithP2());
        isTrue("the fixed pairing is e(P_pub-e, P2)", g.equals(
            SM9Pairing.pairing(SM9Curve.G1.decodePoint(masterPublic.getEncoded()), SM9Curve.P2)));

        SM9KEMGenerator gen = new SM9KEMGenerator(klen, new TestRandomBigInteger(256, SM9Vectors.hex(v, "r")));
        SecretWithEncapsulation enc = gen.generateEncapsulated(recipient);
        isTrue("SM9 KEM key K", Arrays.areEqual(enc.getSecret(), SM9Vectors.hex(v, "K")));
        isTrue("SM9 KEM encapsulation C",
            Arrays.areEqual(enc.getEncapsulation(), Arrays.concatenate(SM9Vectors.hex(v, "C_x"), SM9Vectors.hex(v, "C_y"))));

        SM9EncPrivateKeyParameters userKey = master.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);
        SM9KEMExtractor extractor = new SM9KEMExtractor(userKey, klen);
        isTrue("SM9 KEM decapsulation", Arrays.areEqual(extractor.extractSecret(enc.getEncapsulation()), SM9Vectors.hex(v, "K")));

        // a key-exchange user key must not decapsulate or decrypt: the usages are kept on separate keys
        SM9EncPrivateKeyParameters exchangeKey = master.generateExchangeKey(identity);
        try
        {
            new SM9KEMExtractor(exchangeKey, klen);
            fail("SM9KEMExtractor accepted a key-exchange user key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 KEM decapsulation requires an encryption user key, not a key-exchange key".equals(e.getMessage()));
        }
        try
        {
            new SM9Engine().init(false, exchangeKey);
            fail("SM9Engine accepted a key-exchange user key for decryption");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 decryption requires an encryption user key, not a key-exchange key".equals(e.getMessage()));
        }

        // ... nor does either sender take a recipient key formed under HID_EXCHANGE
        checkExchangeHidRecipientRefused(master, identity, klen);

        // a key length that is not positive, for which the KDF gives no output, or not a whole number of
        // bytes, is refused at construction, before an ephemeral or a pairing is spent
        int[] generatorLengths = { 0, 12 };
        int[] extractorLengths = { -8, 12 };
        String[] lengthMessages = { "keyLenBits must be positive", "keyLenBits must be a whole number of bytes" };
        for (int i = 0; i != lengthMessages.length; i++)
        {
            try
            {
                new SM9KEMGenerator(generatorLengths[i], new TestRandomBigInteger(256, SM9Vectors.hex(v, "r")));
                fail("SM9KEMGenerator accepted keyLenBits = " + generatorLengths[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(lengthMessages[i].equals(e.getMessage()));
            }
            try
            {
                new SM9KEMExtractor(userKey, extractorLengths[i]);
                fail("SM9KEMExtractor accepted keyLenBits = " + extractorLengths[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(lengthMessages[i].equals(e.getMessage()));
            }
        }

        // the KDF answers only a positive whole number of bytes: rounding a request either way would
        // silently give more or fewer bits than asked for. Integer.MAX_VALUE and MIN_VALUE are there because
        // (klen + 7) / 8 in int arithmetic is negative for both
        int[] badLengths = { 0, -1, -8, 1, 7, 255, Integer.MAX_VALUE, Integer.MIN_VALUE };
        for (int i = 0; i != badLengths.length; i++)
        {
            try
            {
                SM9Sm3.kdf(identity, badLengths[i]);
                fail("SM9 KDF accepted klenBits = " + badLengths[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue("klenBits must be a positive whole number of bytes".equals(e.getMessage()));
            }
        }

        // a long request is the same counter-mode stream a short one is a prefix of
        byte[] longer = SM9Sm3.kdf(identity, 1 << 16);
        isTrue("SM9 KDF output length", longer.length == (1 << 16) / 8);
        isTrue("SM9 KDF extends a shorter request",
            Arrays.areEqual(Arrays.copyOfRange(longer, 0, 32), SM9Sm3.kdf(identity, 256)));

        // H1 and H2 reduce mod n - 1, so an n below 2 is refused
        BigInteger[] badModuli = { BigInteger.ONE, BigInteger.ZERO, BigInteger.valueOf(-5) };
        for (int i = 0; i != badModuli.length; i++)
        {
            try
            {
                SM9Sm3.h1(identity, badModuli[i]);
                fail("SM9 H1 accepted n = " + badModuli[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue("n must be at least 2".equals(e.getMessage()));
            }
        }

        // hlen = 8 * ceil(5 * log2(n) / 32) for the logarithm itself, which n's bit length gives only for
        // some n: 8 bits, not 16, at n = 64 and 40, not 48, at n = 2^32; at SM9's N the two agree, at 40 bytes
        BigInteger[] moduli = { BigInteger.valueOf(64), BigInteger.ONE.shiftLeft(32), SM9Curve.N };
        int[] hlenBytes = { 1, 5, 40 };
        for (int i = 0; i != moduli.length; i++)
        {
            isTrue("SM9 H1 hlen for n = " + moduli[i],
                referenceHash((byte)0x01, identity, moduli[i], hlenBytes[i]).equals(SM9Sm3.h1(identity, moduli[i])));
            isTrue("SM9 H2 hlen for n = " + moduli[i],
                referenceHash((byte)0x02, identity, moduli[i], hlenBytes[i]).equals(SM9Sm3.h2(identity, moduli[i])));
        }
    }

    /**
     * H1 / H2 (GM/T 0044.2 5.4.2.2, 5.4.2.3) for an hlen of at most two SM3 outputs: the leftmost
     * hlenBytes of SM3(prefix || Z || 1) || SM3(prefix || Z || 2), reduced mod n - 1, plus one.
     */
    private static BigInteger referenceHash(byte prefix, byte[] z, BigInteger n, int hlenBytes)
    {
        byte[] ha = new byte[64];
        for (int ct = 1; ct <= 2; ct++)
        {
            SM3Digest sm3 = new SM3Digest();
            sm3.update(prefix);
            sm3.update(z, 0, z.length);
            sm3.update(new byte[]{ 0, 0, 0, (byte)ct }, 0, 4);
            sm3.doFinal(ha, (ct - 1) * 32);
        }
        return new BigInteger(1, Arrays.copyOfRange(ha, 0, hlenBytes))
            .mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    /**
     * Both senders refuse a recipient key formed under HID_EXCHANGE, under which generateUserKey derives no
     * KEM / decryption key, while any other hid a KGC publishes still round-trips on both paths.
     */
    private void checkExchangeHidRecipientRefused(SM9EncMasterPrivateKeyParameters master, byte[] identity, int klen)
        throws Exception
    {
        SM9EncMasterPublicKeyParameters masterPublic = master.getPublicKeyParameters();
        SM9EncPublicKeyParameters exchangeRecipient =
            masterPublic.getUserPublicKey(identity, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
        try
        {
            new SM9KEMGenerator(klen, CryptoServicesRegistrar.getSecureRandom()).generateEncapsulated(exchangeRecipient);
            fail("SM9KEMGenerator encapsulated to a recipient key under HID_EXCHANGE");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(("SM9 KEM encapsulation requires an encryption recipient key, not a key-exchange key under "
                + "HID_EXCHANGE (0x02)").equals(e.getMessage()));
        }
        // a key of the wrong kind - the master public key itself, say - is refused by name, as SM9Engine refuses it
        try
        {
            new SM9KEMGenerator(klen, CryptoServicesRegistrar.getSecureRandom()).generateEncapsulated(masterPublic);
            fail("SM9KEMGenerator encapsulated to a master public key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(),
                "SM9 KEM encapsulation requires an SM9EncPublicKeyParameters recipient key".equals(e.getMessage()));
        }
        try
        {
            new SM9Engine().init(true, new ParametersWithRandom(exchangeRecipient, CryptoServicesRegistrar.getSecureRandom()));
            fail("SM9Engine encrypted to a recipient key under HID_EXCHANGE");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(("SM9 encryption requires an encryption recipient key, not a key-exchange key under "
                + "HID_EXCHANGE (0x02)").equals(e.getMessage()));
        }

        byte otherHid = (byte)0x04;
        SM9EncPublicKeyParameters recipient = masterPublic.getUserPublicKey(identity, otherHid);
        SM9EncPrivateKeyParameters userKey = master.generateUserKey(identity, otherHid);
        SecretWithEncapsulation enc = new SM9KEMGenerator(klen, CryptoServicesRegistrar.getSecureRandom())
            .generateEncapsulated(recipient);
        isTrue("a KEM recipient key under a KGC-chosen hid still round-trips",
            Arrays.areEqual(enc.getSecret(), new SM9KEMExtractor(userKey, klen).extractSecret(enc.getEncapsulation())));
        byte[] message = new byte[20];
        SM9Engine encryptor = new SM9Engine(SM9Engine.Mode.STREAM);
        encryptor.init(true, new ParametersWithRandom(recipient, CryptoServicesRegistrar.getSecureRandom()));
        byte[] ciphertext = encryptor.processBlock(message, 0, message.length);
        SM9Engine decryptor = new SM9Engine(SM9Engine.Mode.STREAM);
        decryptor.init(false, userKey);
        isTrue("an encryption recipient key under a KGC-chosen hid still round-trips",
            Arrays.areEqual(message, decryptor.processBlock(ciphertext, 0, ciphertext.length)));
    }

    /**
     * SM9KEMExtractor refuses every encapsulation it cannot decapsulate as "invalid SM9 KEM encapsulation",
     * one with a coordinate at or above the field prime included, a message the JDK 21 KEM path carries
     * into a DecapsulateException.
     */
    private void checkMalformedEncapsulation(SM9EncMasterPrivateKeyParameters master, byte[] identity, int klen)
        throws Exception
    {
        SM9EncPrivateKeyParameters userKey = master.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);
        SM9KEMExtractor extractor = new SM9KEMExtractor(userKey, klen);
        byte[] valid = new SM9KEMGenerator(klen, CryptoServicesRegistrar.getSecureRandom())
            .generateEncapsulated(master.getPublicKeyParameters().getUserPublicKey(identity)).getEncapsulation();
        isTrue("a valid encapsulation extracts", extractor.extractSecret(valid).length == klen / 8);

        // x = q, not a field element, with y left zero; a valid encapsulation with a byte after it, which
        // is not to be read up to its first 64 bytes and taken; and one a byte short
        byte[] outOfField = new byte[64];
        System.arraycopy(BigIntegers.asUnsignedByteArray(32, SM9Curve.G1.getField().getCharacteristic()), 0, outOfField, 0, 32);
        byte[][] malformed = { outOfField, Arrays.append(valid, (byte)0x00), new byte[63] };
        String[] what = { "an out-of-field encapsulation coordinate", "an encapsulation with a trailing byte",
            "a short encapsulation" };
        String[] labels = { "SM9KEMExtractor reports an out-of-field coordinate as its own message, not the field's: ", null,
            "SM9KEMExtractor short-encapsulation message: " };
        for (int i = 0; i != malformed.length; i++)
        {
            try
            {
                extractor.extractSecret(malformed[i]);
                fail("SM9KEMExtractor accepted " + what[i]);
            }
            catch (IllegalArgumentException e)
            {
                if (labels[i] == null)
                {
                    isTrue("invalid SM9 KEM encapsulation".equals(e.getMessage()));
                }
                else
                {
                    isTrue(labels[i] + e.getMessage(), "invalid SM9 KEM encapsulation".equals(e.getMessage()));
                }
            }
        }
    }

    /**
     * A source that yields nothing usable - only zeros, or only ones - is refused once the draws allowed are
     * used up, rather than hanging or having a fallback stand in for r. These run out after 256 draws, so a
     * draw without a bound fails the test rather than hanging it.
     */
    private void checkUnusableSource(SM9EncPublicKeyParameters recipient, int klen)
    {
        for (int fill = 0x00; fill <= 0xFF; fill += 0xFF)
        {
            byte[] source = new byte[32 * 256];
            Arrays.fill(source, (byte)fill);
            try
            {
                new SM9KEMGenerator(klen, new FixedSecureRandom(source)).generateEncapsulated(recipient);
                fail("SM9 KEM encapsulated with a source that yields only 0x" + Integer.toHexString(fill));
            }
            catch (IllegalStateException e)
            {
                isTrue("SM9 encapsulation could not draw a usable ephemeral".equals(e.getMessage()));
            }
        }
    }

    /**
     * Q_B = [H1(ID || hid, N)]P1 + P_pub-e is the point at infinity for ke = N - H1(ID || hid, N): the
     * identity the KGC can derive no user key for, which the KGC and each sender refuse in the same terms.
     */
    private void checkDegenerateRecipientPoint()
        throws Exception
    {
        byte[] identity = "Bob".getBytes("US-ASCII");
        byte hid = SM9EncMasterPrivateKeyParameters.HID;
        BigInteger h1 = SM9Sm3.h1(Arrays.append(identity, hid), SM9Curve.N);
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(SM9Curve.N.subtract(h1));
        SM9EncMasterPublicKeyParameters publicKey = master.getPublicKeyParameters();
        String message = "SM9 encryption master key must be regenerated for this identity";

        // the KGC refuses to derive the key ...
        try
        {
            master.generateUserKey(identity, hid);
            fail("SM9 KGC derived a user key for a degenerate identity");
        }
        catch (IllegalStateException e)
        {
            isTrue(message.equals(e.getMessage()));
        }

        // ... the sender's recipient point
        try
        {
            publicKey.recipientPoint(identity, hid);
            fail("SM9 recipientPoint returned the point at infinity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(message.equals(e.getMessage()));
        }

        // ... its multiple by an ephemeral, formed without forming the point
        try
        {
            publicKey.multiplyRecipientPoint(identity, hid, BigInteger.valueOf(7));
            fail("SM9 multiplyRecipientPoint returned the point at infinity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(message.equals(e.getMessage()));
        }

        SM9EncPublicKeyParameters recipient = publicKey.getUserPublicKey(identity, hid);
        try
        {
            new SM9KEMGenerator(128, CryptoServicesRegistrar.getSecureRandom())
                .generateEncapsulated(recipient);
            fail("SM9 KEM encapsulated to a degenerate recipient point");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(message.equals(e.getMessage()));
        }

        // the engine reports it as the checked exception processBlock declares - for a message the SM4 mode
        // would otherwise encrypt, 16 bytes or more, so the recipient point is all there is to refuse
        SM9Engine engine = new SM9Engine(SM9Engine.Mode.SM4);
        engine.init(true, new ParametersWithRandom(recipient, CryptoServicesRegistrar.getSecureRandom()));
        byte[] m = "hello sm9 encryption".getBytes("US-ASCII");
        try
        {
            engine.processBlock(m, 0, m.length);
            fail("SM9Engine encrypted to a degenerate recipient point");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue(message.equals(e.getMessage()));
        }
    }

    /**
     * multiplyRecipientPoint, [r h1]P1 + [r]P_pub-e without forming Q, is held to recipientPoint's point times r
     * by the default multiplier under three hids, over the ends of r's range and random r; to an affine result;
     * to making P_pub-e's comb table on the first call, not before, and keeping it with the key; and to
     * refusing an r outside [1, N-1] and a null or empty identity, as recipientPoint refuses them.
     */
    private void checkMultiplyRecipientPoint()
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N;
        SM9EncMasterPublicKeyParameters master = new SM9EncMasterPrivateKeyParameters(
            BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).getPublicKeyParameters();
        java.lang.reflect.Field point = SM9EncMasterPublicKeyParameters.class.getDeclaredField("pPube");
        point.setAccessible(true);
        ECPoint ppub = (ECPoint)point.get(master);
        java.lang.reflect.Field name = Class.forName("org.bouncycastle.math.ec.sm9.SM9G1Multiplier")
            .getDeclaredField("PRECOMP_NAME");
        name.setAccessible(true);
        String combName = (String)name.get(null);
        isTrue("P_pub-e keeps no table before the key is multiplied", SM9Curve.G1.getPreCompInfo(ppub, combName) == null);

        byte[] identity = "Bob".getBytes("US-ASCII");
        byte[] hids = { SM9EncMasterPrivateKeyParameters.HID, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE, 0x7F };
        BigInteger[] edges = { BigInteger.ONE, BigInteger.valueOf(2), n.subtract(BigInteger.valueOf(2)), n.subtract(BigInteger.ONE) };
        PreCompInfo table = null;
        for (int h = 0; h != hids.length; h++)
        {
            ECPoint q = master.recipientPoint(identity, hids[h]);
            for (int i = 0; i != edges.length + 8; i++)
            {
                BigInteger r = (i < edges.length) ? edges[i]
                    : BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
                ECPoint c = master.multiplyRecipientPoint(identity, hids[h], r);
                isTrue("multiplyRecipientPoint gives [r]Q under hid " + hids[h] + " for r = " + r.toString(16),
                    c.equals(q.multiply(r)));
                isTrue("multiplyRecipientPoint gives an affine point", c.isNormalized());
                if (table == null)
                {
                    table = SM9Curve.G1.getPreCompInfo(ppub, combName);
                    isTrue("the first multiplication keeps P_pub-e's table with the key", table != null);
                }
            }
        }
        isTrue("the table the first multiplication made is the one kept", SM9Curve.G1.getPreCompInfo(ppub, combName) == table);

        BigInteger[] outside = { null, BigInteger.ZERO, n, n.add(BigInteger.ONE), BigInteger.valueOf(-1) };
        for (int i = 0; i != outside.length; i++)
        {
            try
            {
                master.multiplyRecipientPoint(identity, SM9EncMasterPrivateKeyParameters.HID, outside[i]);
                fail("SM9 multiplyRecipientPoint accepted r = " + outside[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue("SM9 ephemeral r must be in [1, N-1]".equals(e.getMessage()));
            }
        }
        try
        {
            master.multiplyRecipientPoint(null, SM9EncMasterPrivateKeyParameters.HID, BigInteger.ONE);
            fail("SM9 multiplyRecipientPoint accepted a null identity");
        }
        catch (NullPointerException e)
        {
            isTrue("identity cannot be null".equals(e.getMessage()));
        }
        try
        {
            master.multiplyRecipientPoint(new byte[0], SM9EncMasterPrivateKeyParameters.HID, BigInteger.ONE);
            fail("SM9 multiplyRecipientPoint accepted an empty identity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("identity cannot be empty".equals(e.getMessage()));
        }
    }

    public static void main(String[] args)
    {
        runTest(new SM9KEMTest());
    }
}
