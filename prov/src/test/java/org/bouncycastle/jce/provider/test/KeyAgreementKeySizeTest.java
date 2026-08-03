package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.SM2KeyExchangeSpec;
import org.bouncycastle.jcajce.spec.SM9KeyExchangeSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * KeyAgreement.generateSecret(String) declares only NoSuchAlgorithmException and
 * InvalidKeyException, so a key size it cannot satisfy has to be reported as one of those rather
 * than as an unchecked exception escaping from underneath.
 * <p>
 * Without a KDF the derived key can only be taken from the shared secret itself, so asking for a
 * key longer than the secret used to overrun the copy with an ArrayIndexOutOfBoundsException. The
 * exposure is any agreement whose secret is shorter than the requested key: KeyAgreement.SM2
 * always (SM2KeyExchange is driven at a fixed 128 bits), KeyAgreement.SM9 whenever the agreed
 * length in its SM9KeyExchangeSpec is shorter than the request (128 bits by default), and plain
 * ECDH on any curve below 256 bits when 256-bit AES is asked for. The malformed forms of the
 * explicit "[keySize]" suffix escaped as NumberFormatException / StringIndexOutOfBoundsException
 * in the same way, with or without a KDF.
 * </p>
 */
public class KeyAgreementKeySizeTest
    extends SimpleTest
{
    private static final byte[] ID_A = Strings.toByteArray("ALICE123@YAHOO.COM");
    private static final byte[] ID_B = Strings.toByteArray("BILL456@YAHOO.COM");

    private static final String AES_OID = "2.16.840.1.101.3.4.1.42";       // aes256-CBC
    private static final String DESEDE_OID = "1.2.840.113549.3.7";         // des-EDE3-CBC

    private KeyPair sm2StaticA;
    private KeyPair sm2EphemeralA;
    private KeyPair sm2StaticB;
    private KeyPair sm2EphemeralB;

    public String getName()
    {
        return "KeyAgreementKeySize";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM2", "BC");

        sm2StaticA = kpGen.generateKeyPair();
        sm2EphemeralA = kpGen.generateKeyPair();
        sm2StaticB = kpGen.generateKeyPair();
        sm2EphemeralB = kpGen.generateKeyPair();

        sm2OverlongKeyRejected();
        sm2SatisfiableKeySizes();
        sm2SurvivesAFailedRequest();
        sm9OverlongKeyRejected();
        ecdhShortCurveRejected();
        malformedKeySizeRejected();
        kdfPathUnaffected();
        sm4KeySizeResolved();
        unrecognisedNameStillReturnsSecret();
    }

    /**
     * SM4 (GB/T 32907-2016) takes a 128-bit key in every mode. Before its entries were added it was
     * not in the key-size table at all, so the derived key came out at whatever length the agreement
     * happened to produce - which for the SM4 key-wrap OIDs is the key-encryption key a CMS
     * key-agreement recipient uses, and SM4 rejects any length but 16 bytes.
     */
    private void sm4KeySizeResolved()
        throws Exception
    {
        String sm4Wrap = GMObjectIdentifiers.sms4_wrap.getId();
        String sm4WrapPad = GMObjectIdentifiers.sms4_wrap_pad.getId();

        // by name, and from agreements whose secret is longer than 128 bits
        expectKey(sm2Agreement(), "SM4", "SM4", 16);
        expectKey(ecdhAgreement("ECDH", "secp256r1"), "SM4", "SM4", 16);
        expectKey(ecdhAgreement("ECDHwithSHA256KDF", "secp256r1"), "SM4", "SM4", 16);

        // by OID - the shape JceKeyAgreeRecipient uses, where the OID names the key wrap. Both
        // flavours of agreement: with a KDF this used to fail outright as an unknown algorithm,
        // without one it silently produced a KEK of the full secret length.
        String[] agreements = new String[]{"ECDH", "ECDHwithSHA256KDF"};

        for (int i = 0; i != agreements.length; i++)
        {
            expectKey(ecdhAgreement(agreements[i], "secp256r1"), sm4Wrap, "SM4", 16);
            expectKey(ecdhAgreement(agreements[i], "secp256r1"), sm4WrapPad, "SM4", 16);
            expectKey(ecdhAgreement(agreements[i], "secp256r1"),
                GMObjectIdentifiers.sms4_cbc.getId(), "SM4", 16);
            expectKey(ecdhAgreement(agreements[i], "secp256r1"),
                GMObjectIdentifiers.sms4_gcm.getId(), "SM4", 16);
            expectKey(ecdhAgreement(agreements[i], "secp256r1"),
                GMObjectIdentifiers.sms4_ccm.getId(), "SM4", 16);
        }

        // the point of the exercise: the derived KEK actually works as an SM4 key wrap
        SecretKey kek = ecdhAgreement("ECDHwithSHA256KDF", "secp256r1").generateSecret(sm4Wrap);
        SecretKey cek = new SecretKeySpec(new byte[16], "SM4");

        Cipher wrapper = Cipher.getInstance(sm4Wrap, "BC");
        wrapper.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = wrapper.wrap(cek);

        Cipher unwrapper = Cipher.getInstance(sm4Wrap, "BC");
        unwrapper.init(Cipher.UNWRAP_MODE, kek);
        Key recovered = unwrapper.unwrap(wrapped, "SM4", Cipher.SECRET_KEY);

        isTrue("SM4 key wrap round trip failed", areEqual(cek.getEncoded(), recovered.getEncoded()));

        // sms4_xts is deliberately absent - XTS takes a double-length key and BC registers no SM4
        // XTS, so it must not be answered with 128 bits. It stays an unrecognised name.
        expectKey(ecdhAgreement("ECDH", "secp256r1"), GMObjectIdentifiers.sms4_xts.getId(),
            GMObjectIdentifiers.sms4_xts.getId(), 32);
    }

    /**
     * The reported defect: SM2KeyExchange is always driven at 128 bits, so anything wanting more
     * than 16 bytes of key material used to fall off the end of the shared secret.
     */
    private void sm2OverlongKeyRejected()
        throws Exception
    {
        expectNoSuchAlgorithm(sm2Agreement(), "AES",
            "unable to generate 256 bit key for " + AES_OID + ": shared secret is only 128 bits, use a KDF based agreement");
        expectNoSuchAlgorithm(sm2Agreement(), "DESede",
            "unable to generate 192 bit key for " + DESEDE_OID + ": shared secret is only 128 bits, use a KDF based agreement");
        expectNoSuchAlgorithm(sm2Agreement(), "AES[256]",
            "unable to generate 256 bit key for AES[256]: shared secret is only 128 bits, use a KDF based agreement");
        expectNoSuchAlgorithm(sm2Agreement(), "AES[192]",
            "unable to generate 192 bit key for AES[192]: shared secret is only 128 bits, use a KDF based agreement");
    }

    /**
     * Compatibility assertions: everything SM2 could satisfy before still comes back unchanged.
     */
    private void sm2SatisfiableKeySizes()
        throws Exception
    {
        isEquals("SM2 raw secret length", 16, sm2Agreement().generateSecret().length);

        expectKey(sm2Agreement(), "AES[128]", "AES", 16);
        expectKey(sm2Agreement(), "Blowfish", "Blowfish", 16);
        expectKey(sm2Agreement(), "DES", "DES", 8);
    }

    /**
     * A rejected request must not damage the agreement - the shared secret is cleared down on the
     * way out, and that has to be the copy handed to the derivation step, not the SPI's own.
     */
    private void sm2SurvivesAFailedRequest()
        throws Exception
    {
        KeyAgreement agreement = sm2Agreement();

        byte[] expected = sm2Agreement().generateSecret();

        expectNoSuchAlgorithm(agreement, "AES",
            "unable to generate 256 bit key for " + AES_OID + ": shared secret is only 128 bits, use a KDF based agreement");

        SecretKey key = agreement.generateSecret("AES[128]");

        isTrue("agreement damaged by a rejected request", areEqual(expected, key.getEncoded()));
    }

    /**
     * KeyAgreement.SM9 derives exactly the number of bits its SM9KeyExchangeSpec asks for - 128 by
     * default - so it is length-constrained in the same way SM2 is, and on its default path. A
     * request the agreed length cannot cover has to be reported, and one it can cover must still
     * agree between the two parties.
     */
    private void sm9OverlongKeyRejected()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);

        KeyPair master = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)master.getPrivate();
        SM9EncMasterPublicKey masterPub = (SM9EncMasterPublicKey)master.getPublic();

        byte[] idA = Strings.toByteArray("Alice");
        byte[] idB = Strings.toByteArray("Bob");
        byte hid = SM9EncMasterPublicKey.HID_EXCHANGE;

        KeyPair a = masterPriv.generateExchangeKeyPair(idA);
        KeyPair b = masterPriv.generateExchangeKeyPair(idB);

        // the default 128-bit agreed length cannot cover 256-bit AES or 192-bit DESede
        expectNoSuchAlgorithm(sm9Agreement(masterPub, a, b, idA, idB, hid, 128, true), "AES",
            "unable to generate 256 bit key for " + AES_OID + ": shared secret is only 128 bits, use a KDF based agreement");
        expectNoSuchAlgorithm(sm9Agreement(masterPub, a, b, idA, idB, hid, 128, true), "DESede",
            "unable to generate 192 bit key for " + DESEDE_OID + ": shared secret is only 128 bits, use a KDF based agreement");
        expectNoSuchAlgorithm(sm9Agreement(masterPub, a, b, idA, idB, hid, 128, true), "AES[256]",
            "unable to generate 256 bit key for AES[256]: shared secret is only 128 bits, use a KDF based agreement");

        // an agreed length that does cover the request is unaffected...
        expectKey(sm9Agreement(masterPub, a, b, idA, idB, hid, 256, true), "AES", "AES", 32);
        expectKey(sm9Agreement(masterPub, a, b, idA, idB, hid, 128, true), "AES[128]", "AES", 16);

        // ...and still agrees with the other party, so the guard has not disturbed the exchange.
        // Both sides have to be completed inside one exchange - the ephemerals are generated in the
        // provider, so a second run of the helper would be an unrelated exchange.
        KeyAgreement aAgree = KeyAgreement.getInstance("SM9", "BC");
        aAgree.init(a.getPrivate(), new SM9KeyExchangeSpec(true, 256), random);
        Key ra = aAgree.doPhase(masterPub.getUserPublicKey(idB, hid), false);

        KeyAgreement bAgree = KeyAgreement.getInstance("SM9", "BC");
        bAgree.init(b.getPrivate(), new SM9KeyExchangeSpec(false, 256), random);
        Key rb = bAgree.doPhase(masterPub.getUserPublicKey(idA, hid), false);

        aAgree.doPhase(masterPub.getExchangeEphemeral(rb.getEncoded()), true);
        bAgree.doPhase(masterPub.getExchangeEphemeral(ra.getEncoded()), true);

        isTrue("SM9 parties disagree on the derived key",
            areEqual(aAgree.generateSecret("AES").getEncoded(), bAgree.generateSecret("AES").getEncoded()));
    }

    /**
     * Runs both SM9 phases and returns the agreement of the party named by {@code self}, ready for
     * generateSecret. The ephemeral values are generated inside the provider, so both sides have to
     * be driven to complete either one.
     */
    private KeyAgreement sm9Agreement(SM9EncMasterPublicKey masterPub, KeyPair self, KeyPair peer,
                                      byte[] selfId, byte[] peerId, byte hid, int keyLengthBits,
                                      boolean initiator)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        KeyAgreement selfAgree = KeyAgreement.getInstance("SM9", "BC");
        selfAgree.init(self.getPrivate(), new SM9KeyExchangeSpec(initiator, keyLengthBits), random);
        Key selfR = selfAgree.doPhase(masterPub.getUserPublicKey(peerId, hid), false);

        KeyAgreement peerAgree = KeyAgreement.getInstance("SM9", "BC");
        peerAgree.init(peer.getPrivate(), new SM9KeyExchangeSpec(!initiator, keyLengthBits), random);
        Key peerR = peerAgree.doPhase(masterPub.getUserPublicKey(selfId, hid), false);

        selfAgree.doPhase(masterPub.getExchangeEphemeral(peerR.getEncoded()), true);

        return selfAgree;
    }

    /**
     * Not an SM2-only exposure: plain ECDH hands back one field element, so any curve below 256
     * bits cannot satisfy the 256-bit key that the bare name "AES" asks for.
     */
    private void ecdhShortCurveRejected()
        throws Exception
    {
        String[] shortCurves = new String[]{"secp192r1", "secp224r1"};
        int[] secretBits = new int[]{192, 224};

        for (int i = 0; i != shortCurves.length; i++)
        {
            expectNoSuchAlgorithm(ecdhAgreement("ECDH", shortCurves[i]), "AES",
                "unable to generate 256 bit key for " + AES_OID + ": shared secret is only " + secretBits[i] + " bits, use a KDF based agreement");
        }

        // 256 bits of secret is exactly enough - the case that kept this defect hidden.
        expectKey(ecdhAgreement("ECDH", "secp256r1"), "AES", "AES", 32);
    }

    /**
     * An explicit "[keySize]" that cannot be read as a usable key size is a bad algorithm request,
     * not a crash. Applies with or without a KDF, since the size is parsed before either runs.
     */
    private void malformedKeySizeRejected()
        throws Exception
    {
        String[] agreements = new String[]{"ECDH", "ECDHwithSHA256KDF"};

        for (int i = 0; i != agreements.length; i++)
        {
            String agreement = agreements[i];

            expectNoSuchAlgorithm(ecdhAgreement(agreement, "secp256r1"), "AES[",
                "missing closing bracket on key size for algorithm: AES[");
            expectNoSuchAlgorithm(ecdhAgreement(agreement, "secp256r1"), "AES[]",
                "unable to parse key size for algorithm: AES[]");
            expectNoSuchAlgorithm(ecdhAgreement(agreement, "secp256r1"), "AES[abc]",
                "unable to parse key size for algorithm: AES[abc]");
            expectNoSuchAlgorithm(ecdhAgreement(agreement, "secp256r1"), "AES[999999999999]",
                "unable to parse key size for algorithm: AES[999999999999]");
            expectNoSuchAlgorithm(ecdhAgreement(agreement, "secp256r1"), "AES[0]",
                "key size must be a positive multiple of 8 for algorithm: AES[0]");
            expectNoSuchAlgorithm(ecdhAgreement(agreement, "secp256r1"), "AES[7]",
                "key size must be a positive multiple of 8 for algorithm: AES[7]");
            expectNoSuchAlgorithm(ecdhAgreement(agreement, "secp256r1"), "AES[-8]",
                "key size must be a positive multiple of 8 for algorithm: AES[-8]");
        }
    }

    /**
     * A KDF expands to whatever length is asked for, so it is never length-constrained by the
     * shared secret and its handling of an unrecognised name is unchanged.
     */
    private void kdfPathUnaffected()
        throws Exception
    {
        expectKey(ecdhAgreement("ECDHwithSHA256KDF", "secp256r1"), "AES", "AES", 32);
        expectKey(ecdhAgreement("ECDHwithSHA256KDF", "secp192r1"), "AES", "AES", 32);
        expectKey(ecdhAgreement("ECDHwithSHA256KDF", "secp192r1"), "AES[512]", "AES", 64);

        expectNoSuchAlgorithm(ecdhAgreement("ECDHwithSHA256KDF", "secp256r1"), "AES256",
            "unknown algorithm encountered: AES256");
    }

    /**
     * Deliberately left alone: with no KDF an algorithm name carrying no known key size still
     * yields the whole shared secret under the caller's own label. Tightening that to match the
     * KDF path above would break callers using it to label a raw secret.
     */
    private void unrecognisedNameStillReturnsSecret()
        throws Exception
    {
        expectKey(sm2Agreement(), "AES256", "AES256", 16);
        expectKey(ecdhAgreement("ECDH", "secp192r1"), "ChaCha20", "ChaCha20", 24);
    }

    private KeyAgreement sm2Agreement()
        throws Exception
    {
        KeyAgreement agreement = KeyAgreement.getInstance("SM2", "BC");

        agreement.init(sm2StaticA.getPrivate(),
            new SM2KeyExchangeSpec(true, sm2EphemeralA.getPrivate(), sm2EphemeralB.getPublic(), ID_A, ID_B));
        agreement.doPhase(sm2StaticB.getPublic(), true);

        return agreement;
    }

    private KeyAgreement ecdhAgreement(String algorithm, String curve)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDH", "BC");

        kpGen.initialize(new ECNamedCurveGenParameterSpec(curve));

        KeyPair a = kpGen.generateKeyPair();
        KeyPair b = kpGen.generateKeyPair();

        KeyAgreement agreement = KeyAgreement.getInstance(algorithm, "BC");

        agreement.init(a.getPrivate());
        agreement.doPhase(b.getPublic(), true);

        return agreement;
    }

    /**
     * Note there is no catch for RuntimeException here on purpose: an unchecked exception from
     * generateSecret(String) is the defect, so it has to escape and fail the test.
     */
    private void expectNoSuchAlgorithm(KeyAgreement agreement, String algorithm, String expectedMessage)
        throws Exception
    {
        try
        {
            SecretKey key = agreement.generateSecret(algorithm);

            fail("no exception for \"" + algorithm + "\": got a " + key.getEncoded().length + " byte "
                + key.getAlgorithm() + " key");
        }
        catch (NoSuchAlgorithmException e)
        {
            isEquals("wrong message for \"" + algorithm + "\"", expectedMessage, e.getMessage());
        }
    }

    private void expectKey(KeyAgreement agreement, String algorithm, String expectedName, int expectedLength)
        throws Exception
    {
        SecretKey key = agreement.generateSecret(algorithm);

        isEquals("wrong name for \"" + algorithm + "\"", expectedName, key.getAlgorithm());
        isEquals("wrong length for \"" + algorithm + "\"", expectedLength, key.getEncoded().length);
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyAgreementKeySizeTest());
    }
}
