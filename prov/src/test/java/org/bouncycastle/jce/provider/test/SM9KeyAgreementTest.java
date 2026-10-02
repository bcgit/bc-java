package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jcajce.spec.SM9KeyExchangeSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Tests for the SM9 key exchange through {@code KeyAgreement.SM9} (GM/T 0044.3-2016): a two-party
 * agreement over fresh keys, both GM/T 0044.5-2016 Annex B vectors (hid 0x02 and 0x03) reproduced
 * through the JCA API with party A's key imported through SM9EncUserPrivateKeySpec, and the refusals.
 * The ephemerals are generated inside the provider: the first doPhase names the peer and returns this
 * party's R, the last consumes the peer's.
 */
public class SM9KeyAgreementTest
    extends SimpleTest
{
    // one master key pair, and Alice's and Bob's exchange keys under it, for checkAgreement,
    // checkRejections and checkStaleSessionState
    private final byte hid = SM9EncMasterPublicKey.HID_EXCHANGE;
    private SecureRandom random;
    private KeyPairGenerator kpGen;
    private KeyPair master;
    private SM9EncMasterPrivateKey masterPriv;
    private SM9EncMasterPublicKey masterPub;
    private byte[] aliceIdentity;
    private byte[] bobIdentity;
    private KeyPair alice;
    private KeyPair bob;

    public String getName()
    {
        return "SM9KeyAgreement";
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        random = new SecureRandom();
        kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        master = kpGen.generateKeyPair();
        masterPriv = (SM9EncMasterPrivateKey)master.getPrivate();
        masterPub = (SM9EncMasterPublicKey)master.getPublic();
        aliceIdentity = "Alice".getBytes("US-ASCII");
        bobIdentity = "Bob".getBytes("US-ASCII");
        alice = masterPriv.generateExchangeKeyPair(aliceIdentity);
        bob = masterPriv.generateExchangeKeyPair(bobIdentity);

        checkAgreement();
        checkVector("sm9_keyexchange.txt");
        checkVector("sm9_keyexchange_hid03.txt");
        checkRejections();
        checkStaleSessionState();
    }

    /**
     * A rejected call leaves no completed or half-completed agreement for the next to run against: a
     * first phase refused for a third party drops the agreement completed with the second, and a
     * rejected re-init drops the previous key, spec and ephemeral.
     */
    private void checkStaleSessionState()
        throws Exception
    {
        // a complete agreement between Alice and Bob
        KeyAgreement a = KeyAgreement.getInstance("SM9", "BC");
        a.init(alice.getPrivate(), new SM9KeyExchangeSpec(true, 128), random);
        Key ra = a.doPhase(masterPub.getUserPublicKey(bobIdentity, hid), false);
        KeyAgreement b = KeyAgreement.getInstance("SM9", "BC");
        b.init(bob.getPrivate(), new SM9KeyExchangeSpec(false, 128), random);
        Key rb = b.doPhase(masterPub.getUserPublicKey(aliceIdentity, hid), false);
        a.doPhase(rb, true);
        b.doPhase(ra, true);
        byte[] shared = a.generateSecret();
        isTrue("SM9 key agreement completes", Arrays.areEqual(shared, b.generateSecret()));

        // a first phase with Carol, refused for a mismatched hid, must not leave Bob's secret to be
        // handed out as Carol's
        byte[] carolIdentity = "Carol".getBytes("US-ASCII");
        try
        {
            a.doPhase(masterPub.getUserPublicKey(carolIdentity), false);
            fail("KeyAgreement.SM9 accepted a peer key under a mismatched hid");
        }
        catch (InvalidKeyException e)
        {
            isTrue("SM9 key agreement peer key hid does not match this party's key".equals(e.getMessage()));
        }
        try
        {
            byte[] stale = a.generateSecret();
            fail("KeyAgreement.SM9 handed out a previous agreement's secret after a refused first phase: "
                + (Arrays.areEqual(stale, shared) ? "the earlier one" : "some other value"));
        }
        catch (IllegalStateException e)
        {
            // expected - the refused phase dropped the completed agreement
        }

        // a rejected re-init leaves the object uninitialised
        KeyAgreement c = KeyAgreement.getInstance("SM9", "BC");
        c.init(alice.getPrivate(), new SM9KeyExchangeSpec(true, 128), random);
        try
        {
            c.init(master.getPrivate(), new SM9KeyExchangeSpec(true, 128), random);
            fail("KeyAgreement.SM9 accepted a master private key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
        try
        {
            c.doPhase(masterPub.getUserPublicKey(bobIdentity, hid), false);
            fail("KeyAgreement.SM9 ran a phase against the key of a session a rejected init replaced");
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9 key agreement not initialised".equals(e.getMessage()));
        }
    }

    private void checkAgreement()
        throws Exception
    {
        // phase 1: each party names the peer and gets its own ephemeral R back
        KeyAgreement aliceAgree = KeyAgreement.getInstance("SM9", "BC");
        aliceAgree.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
        Key ra = aliceAgree.doPhase(masterPub.getUserPublicKey(bobIdentity, hid), false);

        KeyAgreement bobAgree = KeyAgreement.getInstance("SM9", "BC");
        bobAgree.init(bob.getPrivate(), new SM9KeyExchangeSpec(false), random);
        Key rb = bobAgree.doPhase(masterPub.getUserPublicKey(aliceIdentity, hid), false);

        isTrue("ephemeral encoding is x || y (64 bytes)", ra.getEncoded().length == 64);

        // phase 2: each consumes the peer's R, transported as its 64-byte form
        aliceAgree.doPhase(masterPub.getExchangeEphemeral(rb.getEncoded()), true);
        byte[] aliceSecret = aliceAgree.generateSecret();

        bobAgree.doPhase(masterPub.getExchangeEphemeral(ra.getEncoded()), true);
        byte[] bobSecret = bobAgree.generateSecret();

        isTrue("shared secret is 16 bytes by default", aliceSecret.length == 16);
        isTrue("both parties agree", Arrays.areEqual(aliceSecret, bobSecret));

        // an ephemeral answers one peer value: a further last phase without a new first phase is
        // refused as out of order
        try
        {
            aliceAgree.doPhase(masterPub.getExchangeEphemeral(rb.getEncoded()), true);
            fail("KeyAgreement.SM9 reused its ephemeral for a second last phase");
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9 key agreement requires doPhase with the peer's public key before the peer's ephemeral".equals(e.getMessage()));
        }

        // a new first phase draws a new ephemeral, and the same object agrees again
        Key ra2 = aliceAgree.doPhase(masterPub.getUserPublicKey(bobIdentity, hid), false);
        isTrue("a new first phase draws a new ephemeral", !Arrays.areEqual(ra.getEncoded(), ra2.getEncoded()));
        KeyAgreement bobAgree2 = KeyAgreement.getInstance("SM9", "BC");
        bobAgree2.init(bob.getPrivate(), new SM9KeyExchangeSpec(false), random);
        Key rb2 = bobAgree2.doPhase(masterPub.getUserPublicKey(aliceIdentity, hid), false);
        aliceAgree.doPhase(masterPub.getExchangeEphemeral(rb2.getEncoded()), true);
        bobAgree2.doPhase(masterPub.getExchangeEphemeral(ra2.getEncoded()), true);
        isTrue("both parties agree on a second exchange",
            Arrays.areEqual(aliceAgree.generateSecret(), bobAgree2.generateSecret()));
    }

    private void checkVector(String fileName)
        throws Exception
    {
        Map v = SM9Vectors.load(fileName);
        byte[] identityA = SM9Vectors.hex(v, "IDA");
        byte[] identityB = SM9Vectors.hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));
        byte vectorHid = (byte)Integer.parseInt((String)v.get("hid"), 16);

        // reconstruct the vector's master key through the KeyFactory PKCS#8 path
        byte[] keScalar = BigIntegers.asUnsignedByteArray(32, new BigInteger((String)v.get("ke"), 16));
        PrivateKeyInfo pkcs8 = new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(keScalar));
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        SM9EncMasterPrivateKey vectorPriv = (SM9EncMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(pkcs8.getEncoded(ASN1Encoding.DER)));
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt),
            Arrays.concatenate(new byte[]{0x04}, SM9Vectors.hex(v, "Ppube_x"), SM9Vectors.hex(v, "Ppube_y")));
        SM9EncMasterPublicKey vectorPub = (SM9EncMasterPublicKey)kf.generatePublic(
            new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER)));

        KeyPair deA = vectorPriv.generateExchangeKeyPair(identityA, vectorHid);
        KeyPair deB = vectorPriv.generateExchangeKeyPair(identityB, vectorHid);

        // party A runs on its key rebuilt through the KeyFactory from the stored encoding - the import
        // a party served by the KGC uses, with no master private key - and reproduces the exchange
        PrivateKey deAImported = kf.generatePrivate(new SM9EncUserPrivateKeySpec(
            deA.getPrivate().getEncoded(), vectorPub, identityA, vectorHid, true));
        SM9EncUserPrivateKeySpec roundTrip = (SM9EncUserPrivateKeySpec)kf.getKeySpec(
            deAImported, SM9EncUserPrivateKeySpec.class);
        isTrue(fileName + " round-trip spec claims the exchange usage", roundTrip.isExchangeKey());
        isTrue(fileName + " round-trip spec hid", roundTrip.getHid() == vectorHid);

        // each ephemeral comes from the SecureRandom the provider is given, so the vector's rA / rB
        // drive it through the public API
        KeyAgreement a = KeyAgreement.getInstance("SM9", "BC");
        a.init(deAImported, new SM9KeyExchangeSpec(true, klen),
            new TestRandomBigInteger(256, SM9Vectors.hex(v, "rA")));
        Key ra = a.doPhase(vectorPub.getUserPublicKey(identityB, vectorHid), false);

        KeyAgreement b = KeyAgreement.getInstance("SM9", "BC");
        b.init(deB.getPrivate(), new SM9KeyExchangeSpec(false, klen),
            new TestRandomBigInteger(256, SM9Vectors.hex(v, "rB")));
        Key rb = b.doPhase(vectorPub.getUserPublicKey(identityA, vectorHid), false);

        isTrue(fileName + " RA", Arrays.areEqual(ra.getEncoded(),
            Arrays.concatenate(SM9Vectors.hex(v, "RA_x"), SM9Vectors.hex(v, "RA_y"))));
        isTrue(fileName + " RB", Arrays.areEqual(rb.getEncoded(),
            Arrays.concatenate(SM9Vectors.hex(v, "RB_x"), SM9Vectors.hex(v, "RB_y"))));

        a.doPhase(vectorPub.getExchangeEphemeral(rb.getEncoded()), true);
        byte[] skA = a.generateSecret();
        b.doPhase(vectorPub.getExchangeEphemeral(ra.getEncoded()), true);
        byte[] skB = b.generateSecret();

        isTrue(fileName + " SKA", Arrays.areEqual(skA, SM9Vectors.hex(v, "SK")));
        isTrue(fileName + " SKB", Arrays.areEqual(skB, SM9Vectors.hex(v, "SK")));
    }

    private void checkRejections()
        throws Exception
    {
        PrivateKey kemKey = masterPriv.generateUserKeyPair(aliceIdentity,
            SM9EncMasterPublicKey.HID).getPrivate();
        KeyAgreement agree = KeyAgreement.getInstance("SM9", "BC");

        // an exchange key's encoding cannot be described as a decryption key: the usage claimed and
        // the hid the point was derived under would name two different keys, so the spec, where both
        // are first in hand, checks the claim against the hid the KGC chose
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        try
        {
            new SM9EncUserPrivateKeySpec(alice.getPrivate().getEncoded(), masterPub, aliceIdentity, hid);
            fail("SM9EncUserPrivateKeySpec described a point derived under HID_EXCHANGE as a decryption key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(("hid must not be HID_EXCHANGE (0x02) for a KEM or decryption user key - that hid "
                + "names the key exchange").equals(e.getMessage()));
        }
        isTrue("the same point and hid describe the exchange key they are", new SM9EncUserPrivateKeySpec(
            alice.getPrivate().getEncoded(), masterPub, aliceIdentity, hid, true).isExchangeKey());

        // a KEM/decryption user key is rejected at init, derived or imported (its encoding still
        // round-trips)
        PrivateKey nonExchange = kf.generatePrivate(new SM9EncUserPrivateKeySpec(
            kemKey.getEncoded(), masterPub, aliceIdentity, SM9EncMasterPublicKey.HID));
        Object[][] notExchange = {
            { kemKey, "a KEM/decryption user key" },
            { nonExchange, "an imported user key without the exchange usage" } };
        for (int i = 0; i != notExchange.length; i++)
        {
            try
            {
                agree.init((PrivateKey)notExchange[i][0], new SM9KeyExchangeSpec(true), random);
                fail("KeyAgreement.SM9 accepted " + (String)notExchange[i][1]);
            }
            catch (InvalidKeyException e)
            {
                isTrue("SM9 key agreement requires a key-exchange user key from SM9EncMasterPrivateKey.generateExchangeKeyPair(identity)"
                    .equals(e.getMessage()));
            }
        }

        // no spec: the role and key length have nowhere else to travel
        try
        {
            agree.init(alice.getPrivate(), random);
            fail("KeyAgreement.SM9 accepted init without a spec");
        }
        catch (InvalidKeyException e)
        {
            // BaseAgreementSpi wraps the missing-spec InvalidAlgorithmParameterException
        }

        // a first phase with the wrong peer key, with the refusal's message where it is checked; the
        // no-hid getUserPublicKey derives the encryption (0x03) key, ours is an exchange (0x02) key
        Object[][] wrongPeers = {
            { master.getPublic(), null, "a master key as the peer" },
            { masterPub.getUserPublicKey(bobIdentity), "SM9 key agreement peer key hid does not match this party's key",
                "a peer key under a mismatched hid" },
            { ((SM9EncMasterPublicKey)kpGen.generateKeyPair().getPublic()).getUserPublicKey(bobIdentity, hid),
                "SM9 key agreement peer key is not under this party's master public key", "a peer key under a different master key" } };
        for (int i = 0; i != wrongPeers.length; i++)
        {
            agree.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
            try
            {
                agree.doPhase((Key)wrongPeers[i][0], false);
                fail("KeyAgreement.SM9 accepted " + (String)wrongPeers[i][2]);
            }
            catch (InvalidKeyException e)
            {
                if (wrongPeers[i][1] != null)
                {
                    isTrue(wrongPeers[i][1].equals(e.getMessage()));
                }
            }
        }

        // the last phase before the first is rejected, not a silent wrong answer. The peer value is a
        // genuine ephemeral: an invalid point is refused before the ordering check is reached
        KeyAgreement bobAgree = KeyAgreement.getInstance("SM9", "BC");
        bobAgree.init(bob.getPrivate(), new SM9KeyExchangeSpec(false), random);
        Key bobEphemeral = bobAgree.doPhase(masterPub.getUserPublicKey(aliceIdentity, hid), false);

        agree.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
        try
        {
            agree.doPhase(bobEphemeral, true);
            fail("KeyAgreement.SM9 accepted the last phase first");
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9 key agreement requires doPhase with the peer's public key before the peer's ephemeral".equals(e.getMessage()));
        }

        // a malformed peer ephemeral is rejected where it is wrapped
        try
        {
            masterPub.getExchangeEphemeral(new byte[10]);
            fail("truncated peer ephemeral accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 exchange ephemeral encoding must be 64 bytes".equals(e.getMessage()));
        }

        // the spec refuses a key length that is not positive, or not a whole number of bytes, which
        // the key comes back in
        int[] badLengths = { 0, -8, 12 };
        String[] lengthRefusals = { "keyLengthBits must be positive", "keyLengthBits must be positive",
            "keyLengthBits must be a whole number of bytes" };
        for (int i = 0; i != badLengths.length; i++)
        {
            try
            {
                new SM9KeyExchangeSpec(true, badLengths[i]);
                fail("SM9KeyExchangeSpec accepted keyLengthBits = " + badLengths[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(lengthRefusals[i].equals(e.getMessage()));
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new SM9KeyAgreementTest());
    }
}
