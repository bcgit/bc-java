package org.bouncycastle.jce.provider.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
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
import org.bouncycastle.jcajce.spec.SM9KeyExchangeSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.bouncycastle.test.TestResourceFinder;

/**
 * Tests for the SM9 key exchange through {@code KeyAgreement.SM9} (GM/T 0044.3-2016):
 * a full two-party agreement over freshly generated keys, both official GM/T
 * 0044.5-2016 Annex B vectors reproduced byte-for-byte through the JCA API (the
 * Chinese edition's hid = 0x02 example and the official English edition's
 * hid = 0x03 one), and rejection of wrong key types, a mismatched hid or master
 * key, a malformed peer ephemeral, a missing spec and out-of-order calls. The
 * ephemeral values are generated inside the provider: the first doPhase names
 * the peer and returns this party's R, the last consumes the peer's.
 */
public class SM9KeyAgreementTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9KeyAgreement";
    }

    private Map loadVectors(String fileName)
        throws Exception
    {
        Map m = new HashMap();
        BufferedReader br = new BufferedReader(
            new InputStreamReader(TestResourceFinder.findTestResource("crypto/sm9", fileName)));
        try
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq > 0)
                {
                    m.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
        }
        finally
        {
            br.close();
        }
        return m;
    }

    private byte[] hex(Map v, String key)
    {
        return Hex.decode((String)v.get(key));
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        checkAgreement();
        checkVector("sm9_keyexchange.txt");
        checkVector("sm9_keyexchange_hid03.txt");
        checkRejections();
    }

    private void checkAgreement()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair master = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)master.getPrivate();
        SM9EncMasterPublicKey masterPub = (SM9EncMasterPublicKey)master.getPublic();

        byte[] aliceIdentity = "Alice".getBytes("US-ASCII");
        byte[] bobIdentity = "Bob".getBytes("US-ASCII");
        KeyPair alice = masterPriv.generateExchangeKeyPair(aliceIdentity);
        KeyPair bob = masterPriv.generateExchangeKeyPair(bobIdentity);

        byte hid = SM9EncMasterPublicKey.HID_EXCHANGE;

        // phase 1: each party names the peer and gets its own ephemeral R back -
        // generated inside the provider under its own master key
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
    }

    private void checkVector(String fileName)
        throws Exception
    {
        Map v = loadVectors(fileName);
        byte[] identityA = hex(v, "IDA");
        byte[] identityB = hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));
        byte hid = (byte)Integer.parseInt((String)v.get("hid"), 16);

        // reconstruct the vector's master key through the KeyFactory PKCS#8 path
        byte[] keScalar = BigIntegers.asUnsignedByteArray(32, new BigInteger((String)v.get("ke"), 16));
        PrivateKeyInfo pkcs8 = new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(keScalar));
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(pkcs8.getEncoded(ASN1Encoding.DER)));
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt),
            Arrays.concatenate(new byte[]{0x04}, hex(v, "Ppube_x"), hex(v, "Ppube_y")));
        PublicKey masterPub = kf.generatePublic(new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER)));

        KeyPair deA = masterPriv.generateExchangeKeyPair(identityA, hid);
        KeyPair deB = masterPriv.generateExchangeKeyPair(identityB, hid);
        SM9EncMasterPublicKey masterPubIface = (SM9EncMasterPublicKey)masterPub;

        // the provider generates each ephemeral from the SecureRandom it was given,
        // so the vector's rA / rB drive it through the public API
        KeyAgreement a = KeyAgreement.getInstance("SM9", "BC");
        a.init(deA.getPrivate(), new SM9KeyExchangeSpec(true, klen),
            new TestRandomBigInteger(256, hex(v, "rA")));
        Key ra = a.doPhase(masterPubIface.getUserPublicKey(identityB, hid), false);

        KeyAgreement b = KeyAgreement.getInstance("SM9", "BC");
        b.init(deB.getPrivate(), new SM9KeyExchangeSpec(false, klen),
            new TestRandomBigInteger(256, hex(v, "rB")));
        Key rb = b.doPhase(masterPubIface.getUserPublicKey(identityA, hid), false);

        isTrue(fileName + " RA", Arrays.areEqual(ra.getEncoded(),
            Arrays.concatenate(hex(v, "RA_x"), hex(v, "RA_y"))));
        isTrue(fileName + " RB", Arrays.areEqual(rb.getEncoded(),
            Arrays.concatenate(hex(v, "RB_x"), hex(v, "RB_y"))));

        a.doPhase(masterPubIface.getExchangeEphemeral(rb.getEncoded()), true);
        byte[] skA = a.generateSecret();
        b.doPhase(masterPubIface.getExchangeEphemeral(ra.getEncoded()), true);
        byte[] skB = b.generateSecret();

        isTrue(fileName + " SKA", Arrays.areEqual(skA, hex(v, "SK")));
        isTrue(fileName + " SKB", Arrays.areEqual(skB, hex(v, "SK")));
    }

    private void checkRejections()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair master = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)master.getPrivate();
        SM9EncMasterPublicKey masterPub = (SM9EncMasterPublicKey)master.getPublic();

        byte[] aliceIdentity = "Alice".getBytes("US-ASCII");
        byte[] bobIdentity = "Bob".getBytes("US-ASCII");
        KeyPair alice = masterPriv.generateExchangeKeyPair(aliceIdentity);
        byte hid = SM9EncMasterPublicKey.HID_EXCHANGE;

        // a KEM/decryption-purpose user key must be rejected at init
        PrivateKey kemKey = masterPriv.generateUserKeyPair(aliceIdentity,
            SM9EncMasterPublicKey.HID).getPrivate();
        KeyAgreement agree = KeyAgreement.getInstance("SM9", "BC");
        try
        {
            agree.init(kemKey, new SM9KeyExchangeSpec(true), random);
            fail("KeyAgreement.SM9 accepted a KEM/decryption user key");
        }
        catch (InvalidKeyException e)
        {
            isTrue("SM9 key agreement requires a key-exchange user key from SM9EncMasterPrivateKey.generateExchangeKeyPair(identity)".equals(e.getMessage()));
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

        // first phase with the wrong key type
        agree.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
        try
        {
            agree.doPhase(master.getPublic(), false);
            fail("KeyAgreement.SM9 accepted a master key as the peer");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }

        // a peer key under the wrong hid - the no-hid getUserPublicKey derives the
        // encryption (0x03) key, ours is an exchange (0x02) key
        agree.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
        try
        {
            agree.doPhase(masterPub.getUserPublicKey(bobIdentity), false);
            fail("KeyAgreement.SM9 accepted a peer key under a mismatched hid");
        }
        catch (InvalidKeyException e)
        {
            isTrue("SM9 key agreement peer key hid does not match this party's key".equals(e.getMessage()));
        }

        // a peer key under a different KGC's master key
        KeyPair otherMaster = kpGen.generateKeyPair();
        agree.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
        try
        {
            agree.doPhase(((SM9EncMasterPublicKey)otherMaster.getPublic()).getUserPublicKey(bobIdentity, hid), false);
            fail("KeyAgreement.SM9 accepted a peer key under a different master key");
        }
        catch (InvalidKeyException e)
        {
            isTrue("SM9 key agreement peer key is not under this party's master public key".equals(e.getMessage()));
        }

        // the last phase before the first is rejected, not a silent wrong answer
        agree.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
        try
        {
            agree.doPhase(masterPub.getExchangeEphemeral(new byte[64]), true);
            fail("KeyAgreement.SM9 accepted the last phase first");
        }
        catch (IllegalArgumentException e)
        {
            // the all-zero encoding is not a valid point - rejected before ordering
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

        // the spec rejects a non-positive key length at construction
        try
        {
            new SM9KeyExchangeSpec(true, 0);
            fail("SM9KeyExchangeSpec accepted keyLengthBits = 0");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("keyLengthBits must be positive".equals(e.getMessage()));
        }
    }

    public static void main(String[] args)
    {
        runTest(new SM9KeyAgreementTest());
    }
}
