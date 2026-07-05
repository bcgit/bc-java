package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

/**
 * Test cases for the use of XMSS^MT with the BCPQC provider.
 */
public class XMSSMTTest
    extends TestCase
{
    private static final byte[] msg = Strings.toByteArray("Cthulhu Fthagn --What a wonderful phrase!Cthulhu Fthagn --Say it and you're crazed!");

    private static byte[] testPrivKey = Base64.decode(
        "MIIHuAIBADAkBgorBgEEAYGwGgIDMBYCAQACAQoCAQIwCwYJYIZIAWUDBAIBBIIHizCCB4cCAQAwgYsCAQAEILF57l4FB6N/vvGoIQ" +
            "TjZ5gaZRgFQUPBjH7y6mfZgdvaBCBvDUjbkmb9GoHYbyKHxGlJ/dmHAkXahPNNfRR9AZCOlwQgBfd9vy9CNN4k4NIYjRvtz7QgMjjb" +
            "kt5WAdQej5KzNM0EIPTPrmKVwjXe4F8QlmZOUZP28jDG/ZJpxR5712m2e4ywoIIG8gSCBu6s7QAFc3IALG9yZy5ib3VuY3ljYXN0bG" +
            "UucHFjLmNyeXB0by54bXNzLkJEU1N0YXRlTWFwz+vLa6D+CbwCAAFMAAhiZHNTdGF0ZXQAD0xqYXZhL3V0aWwvTWFwO3hwc3IAEWph" +
            "dmEudXRpbC5UcmVlTWFwDMH2Pi0lauYDAAFMAApjb21wYXJhdG9ydAAWTGphdmEvdXRpbC9Db21wYXJhdG9yO3hwcHcEAAAAAXNyAB" +
            "FqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IA" +
            "JG9yZy5ib3VuY3ljYXN0bGUucHFjLmNyeXB0by54bXNzLkJEUwAAAAAAAAABAgAKSQAFaW5kZXhJAAFrSQAKdHJlZUhlaWdodFoABH" +
            "VzZWRMABJhdXRoZW50aWNhdGlvblBhdGh0ABBMamF2YS91dGlsL0xpc3Q7TAAEa2VlcHEAfgABTAAGcmV0YWlucQB+AAFMAARyb290" +
            "dAArTG9yZy9ib3VuY3ljYXN0bGUvcHFjL2NyeXB0by94bXNzL1hNU1NOb2RlO0wABXN0YWNrdAARTGphdmEvdXRpbC9TdGFjaztMAB" +
            "F0cmVlSGFzaEluc3RhbmNlc3EAfgAKeHAAAAAAAAAAAwAAAAUAc3IAE2phdmEudXRpbC5BcnJheUxpc3R4gdIdmcdhnQMAAUkABHNp" +
            "emV4cAAAAAV3BAAAAAVzcgApb3JnLmJvdW5jeWNhc3RsZS5wcWMuY3J5cHRvLnhtc3MuWE1TU05vZGUAAAAAAAAAAQIAAkkABmhlaW" +
            "dodFsABXZhbHVldAACW0J4cAAAAAB1cgACW0Ks8xf4BghU4AIAAHhwAAAAIKblKPny5XBcLTom61U/VvUCJ+/xEX/qJaRXitEAu89F" +
            "c3EAfgAQAAAAAXVxAH4AEwAAACDLWNO9lh3R8LdD5dVoQ5r85BH+XbLY3a/Bbf2ABa7AEXNxAH4AEAAAAAJ1cQB+ABMAAAAgv7gBYE" +
            "q+h3U9GsU5dqmQp/p2ap7tr5wv6X8mYVgNJPhzcQB+ABAAAAADdXEAfgATAAAAIDLtl68/OsguE7QTZ2UzFfcjGv3fGoiBomQNlyEs" +
            "VWT1c3EAfgAQAAAABHVxAH4AEwAAACC2CKhUAp92/hJwuyEIJXxBcHsTg/vgBg3FfHaFJh85cXhzcQB+AANwdwQAAAAAeHNxAH4AA3" +
            "B3BAAAAAJzcQB+AAYAAAACc3IAFGphdmEudXRpbC5MaW5rZWRMaXN0DClTXUpgiCIDAAB4cHcEAAAAA3NxAH4AEAAAAAJ1cQB+ABMA" +
            "AAAgl/DnFFIHZ6u8yNQSOIh47zRoRZLfkj8/CzUHM54wKQtzcQB+ABAAAAACdXEAfgATAAAAIPx12RSLQNhXo5DWenzn18i5c11MQ8" +
            "E21a3fKBI1c1xTc3EAfgAQAAAAAnVxAH4AEwAAACAUw9Wnqw/IS+TLVVj5zAOe0lMvf+x3x61nHfjYAXY5BnhzcQB+AAYAAAADc3EA" +
            "fgAgdwQAAAABc3EAfgAQAAAAA3VxAH4AEwAAACC4x1ONSAJrJ0+2gqZxhi6MJ7jY69JS2b425N3ZUAwiKnh4c3EAfgAQAAAABXVxAH" +
            "4AEwAAACD0z65ilcI13uBfEJZmTlGT9vIwxv2SacUee9dptnuMsHNyAA9qYXZhLnV0aWwuU3RhY2sQ/irCuwmGHQIAAHhyABBqYXZh" +
            "LnV0aWwuVmVjdG9y2Zd9W4A7rwEDAANJABFjYXBhY2l0eUluY3JlbWVudEkADGVsZW1lbnRDb3VudFsAC2VsZW1lbnREYXRhdAATW0" +
            "xqYXZhL2xhbmcvT2JqZWN0O3hwAAAAAAAAAAB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAKcHBwcHBwcHBw" +
            "cHhzcQB+AA4AAAACdwQAAAACc3IALG9yZy5ib3VuY3ljYXN0bGUucHFjLmNyeXB0by54bXNzLkJEU1RyZWVIYXNoAAAAAAAAAAECAA" +
            "ZaAAhmaW5pc2hlZEkABmhlaWdodEkADWluaXRpYWxIZWlnaHRaAAtpbml0aWFsaXplZEkACW5leHRJbmRleEwACHRhaWxOb2RlcQB+" +
            "AAt4cAEAAAAAAAAAAAAAAAAAc3EAfgAQAAAAAHVxAH4AEwAAACBIFJAzhXYHQfeDbwNePGtSxwbQECJRTd1ut5zN8RA3yXNxAH4ANQ" +
            "EAAAABAAAAAQAAAAAAc3EAfgAQAAAAAXVxAH4AEwAAACCugtHVqJDME59RRNQ0b2Podg5KdFxCIEOqJbBvwDzxCXh4");

    private static byte[] testPublicKey = Base64.decode(
        "MHIwJAYKKwYBBAGBsBoCAzAWAgEAAgEEAgECMAsGCWCGSAFlAwQCCwNKADBHAgEABCDIZh5Q96JIc0h+AmYHd3UP1ldE5buCIeHXsN" +
            "xBgGEtbAQgxENVtn9cR2bPbe3IZcmy6JmI6fvHt5yMkJ1lgQZFw6A=");

    private static byte[] priv160Pkcs8 = Base64.decode("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");
    private static byte[] priv160Ser = Base64.decode("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");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void test160PrivateKeyRecovery()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTKey privKey = (XMSSMTKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(priv160Pkcs8));

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(priv160Ser));

        XMSSMTKey privKey2 = (XMSSMTKey)oIn.readObject();

        assertEquals(privKey, privKey2);
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTKey privKey = (XMSSMTKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(testPrivKey));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        XMSSMTKey privKey2 = (XMSSMTKey)oIn.readObject();

        assertEquals(privKey, privKey2);
    }

    public void testRFC9802PublicKeyEncoding()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 2, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        // RFC 9802: id-alg-xmssmt-hashsig, absent parameters, raw RFC 8391 key in the BIT STRING.
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        assertEquals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig, keyInfo.getAlgorithm().getAlgorithm());
        assertNull(keyInfo.getAlgorithm().getParameters());

        byte[] rawKey = keyInfo.getPublicKeyData().getOctets();

        KeyFactory kFact = KeyFactory.getInstance("XMSSMT", "BCPQC");

        PublicKey pubKey = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        // the legacy draft form - id_alg_xmssmt with the key wrapped in an OCTET STRING - must still decode.
        SubjectPublicKeyInfo legacy = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmssmt), new DEROctetString(rawKey));

        PublicKey legacyKey = kFact.generatePublic(new X509EncodedKeySpec(legacy.getEncoded()));

        assertEquals(kp.getPublic(), legacyKey);
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTKey pubKey = (XMSSMTKey)kFact.generatePublic(new X509EncodedKeySpec(testPublicKey));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        XMSSMTKey pubKey2 = (XMSSMTKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
    }

    public void testKeyExtraction()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 2, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        StateAwareSignature sig = (StateAwareSignature)Signature.getInstance("XMSSMT-SHA256", "BCPQC");

        sig.initSign(kp.getPrivate());

        assertTrue(sig.isSigningCapable());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        XMSSMTPrivateKey nKey = (XMSSMTPrivateKey)sig.getUpdatedPrivateKey();

        assertTrue(kp.getPrivate().equals(nKey)); // key is mutable.
        assertFalse(sig.isSigningCapable());

        sig.update(msg, 0, msg.length);

        try
        {
            sig.sign();
            fail("no exception after key extraction");
        }
        catch (SignatureException e)
        {
            assertEquals("signing key no longer usable", e.getMessage());
        }

        try
        {
            sig.getUpdatedPrivateKey();
            fail("no exception after key extraction");
        }
        catch (IllegalStateException e)
        {
            assertEquals("signature object not in a signing state", e.getMessage());
        }

        XMSSMTPrivateKey singleUseKey = nKey.extractKeyShard(1);
        sig.initSign(singleUseKey);

        sig.update(msg, 0, msg.length);

        s = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        sig.initSign(singleUseKey);

        sig.update(msg, 0, msg.length);

        try
        {
            s = sig.sign();
            fail("no exception");
        }
        catch (SignatureException e)
        {
            assertEquals("no usages of private key remaining", e.getMessage());
        }
    }

    public void testXMSSMTSha256SignatureMultiple()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        StateAwareSignature sig1 = (StateAwareSignature)Signature.getInstance("SHA256withXMSSMT-SHA256", "BCPQC");

        StateAwareSignature sig2 = (StateAwareSignature)Signature.getInstance("SHA256withXMSSMT-SHA256", "BCPQC");

        StateAwareSignature sig3 = (StateAwareSignature)Signature.getInstance("SHA256withXMSSMT-SHA256", "BCPQC");

        sig1.initSign(kp.getPrivate());

        sig2.initSign(sig1.getUpdatedPrivateKey());

        sig3.initSign(sig2.getUpdatedPrivateKey());

        sig1.update(msg, 0, msg.length);

        byte[] s1 = sig1.sign();

        sig2.update(msg, 0, msg.length);

        byte[] s2 = sig2.sign();

        sig3.update(msg, 0, msg.length);

        byte[] s3 = sig3.sign();

        sig1.initVerify(kp.getPublic());

        sig1.update(msg, 0, msg.length);

        assertTrue(sig1.verify(s1));

        sig1.update(msg, 0, msg.length);

        assertTrue(sig1.verify(s2));

        sig1.update(msg, 0, msg.length);

        assertTrue(sig1.verify(s3));
    }

    public void testXMSSMTSha512KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTKey privKey = (XMSSMTKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSMTKey pubKey = (XMSSMTKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(20, privKey.getHeight());
        assertEquals(10, privKey.getLayers());
        assertEquals(XMSSMTParameterSpec.SHA512, privKey.getTreeDigest());

        assertEquals(20, pubKey.getHeight());
        assertEquals(10, pubKey.getLayers());
        assertEquals(XMSSMTParameterSpec.SHA512, pubKey.getTreeDigest());
    }

    public void testXMSSMTSha256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(10, 5, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testXMSSMTSha512Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(10, 5, XMSSMTParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testXMSSMTShake128Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE128), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("XMSSMT-SHAKE128", "BCPQC");

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testXMSSMTShake256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("XMSSMT-SHAKE256", "BCPQC");

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testSP800208KeyGenAndRoundTrip()
        throws Exception
    {
        String[] treeDigests = {
            XMSSMTParameterSpec.SHA256_192, XMSSMTParameterSpec.SHAKE256_256, XMSSMTParameterSpec.SHAKE256_192};

        for (int i = 0; i != treeDigests.length; i++)
        {
            String treeDigest = treeDigests[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
            kpg.initialize(new XMSSMTParameterSpec(20, 2, treeDigest), new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            // private and public halves share the RFC 9802 algorithm OID
            assertEquals(treeDigest, IANAObjectIdentifiers.id_alg_xmssmt_hashsig,
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
            assertEquals(treeDigest, IANAObjectIdentifiers.id_alg_xmssmt_hashsig,
                PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded()).getPrivateKeyAlgorithm().getAlgorithm());

            // getTreeDigest() reflects the specific SP 800-208 variant (n included)
            assertEquals(treeDigest, ((XMSSMTKey)kp.getPublic()).getTreeDigest());
            assertEquals(treeDigest, ((XMSSMTKey)kp.getPrivate()).getTreeDigest());

            // KeyFactory round-trips both halves to equal keys
            KeyFactory kFact = KeyFactory.getInstance("XMSSMT", "BCPQC");
            PublicKey pubKey = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey privKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            assertEquals(treeDigest, kp.getPublic(), pubKey);
            assertEquals(treeDigest, kp.getPrivate(), privKey);

            // the generated key signs and verifies
            Signature sig = Signature.getInstance("XMSSMT", "BCPQC");
            sig.initSign(kp.getPrivate());
            sig.update(msg, 0, msg.length);
            byte[] s = sig.sign();
            sig.initVerify(kp.getPublic());
            sig.update(msg, 0, msg.length);
            assertTrue(treeDigest, sig.verify(s));
        }
    }

    public void testSignerKeyDigestFamilyEnforcement()
        throws Exception
    {
        KeyPairGenerator shaKpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
        shaKpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHA256), new SecureRandom());
        KeyPair shaKp = shaKpg.generateKeyPair();

        KeyPairGenerator shakeKpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
        shakeKpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE256), new SecureRandom());
        KeyPair shakeKp = shakeKpg.generateKeyPair();

        // a SHA256 key handed to a SHAKE256-named signer is rejected on both init paths
        Signature shakeSig = Signature.getInstance("XMSSMT-SHAKE256", "BCPQC");
        try
        {
            shakeSig.initSign(shaKp.getPrivate());
            fail("no exception on mismatched private key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
        try
        {
            shakeSig.initVerify(shaKp.getPublic());
            fail("no exception on mismatched public key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }

        // ...and the reverse (SHAKE256 key on a SHA256-named signer)
        Signature shaSig = Signature.getInstance("XMSSMT-SHA256", "BCPQC");
        try
        {
            shaSig.initSign(shakeKp.getPrivate());
            fail("no exception on mismatched private key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }

        // a matching key is accepted and round-trips
        shakeSig.initSign(shakeKp.getPrivate());
        shakeSig.update(msg, 0, msg.length);
        byte[] s = shakeSig.sign();
        shakeSig.initVerify(shakeKp.getPublic());
        shakeSig.update(msg, 0, msg.length);
        assertTrue(shakeSig.verify(s));

        // the generic "XMSSMT" signer is lenient - it accepts any key
        Signature genericSig = Signature.getInstance("XMSSMT", "BCPQC");
        genericSig.initSign(shaKp.getPrivate());
        genericSig.update(msg, 0, msg.length);
        byte[] gs = genericSig.sign();
        genericSig.initVerify(shaKp.getPublic());
        genericSig.update(msg, 0, msg.length);
        assertTrue(genericSig.verify(gs));

        // SP 800-208 SHAKE256/256 keys (tree digest id-shake256-len) are within the SHAKE256 family
        KeyPairGenerator sp800Kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
        sp800Kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE256_256), new SecureRandom());
        KeyPair sp800Kp = sp800Kpg.generateKeyPair();

        Signature sp800Sig = Signature.getInstance("XMSSMT-SHAKE256", "BCPQC");
        sp800Sig.initSign(sp800Kp.getPrivate());
        sp800Sig.update(msg, 0, msg.length);
        byte[] sp = sp800Sig.sign();
        sp800Sig.initVerify(sp800Kp.getPublic());
        sp800Sig.update(msg, 0, msg.length);
        assertTrue(sp800Sig.verify(sp));

        // and SHA-256/192 keys are within the SHA256 family
        KeyPairGenerator sha192Kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
        sha192Kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHA256_192), new SecureRandom());
        KeyPair sha192Kp = sha192Kpg.generateKeyPair();

        Signature sha192Sig = Signature.getInstance("XMSSMT-SHA256", "BCPQC");
        sha192Sig.initSign(sha192Kp.getPrivate());
        sha192Sig.update(msg, 0, msg.length);
        byte[] sh = sha192Sig.sign();
        sha192Sig.initVerify(sha192Kp.getPublic());
        sha192Sig.update(msg, 0, msg.length);
        assertTrue(sha192Sig.verify(sh));
    }

    public void testKeyRebuild()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 4, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        sig.initSign(kp.getPrivate());

        for (int i = 0; i != 5; i++)
        {
            sig.update(msg, 0, msg.length);

            sig.sign();
        }

        XMSSMTPrivateKey pKey = (XMSSMTPrivateKey)kp.getPrivate();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");

        // Reconstruct the legacy (pre-1.85) PQCObjectIdentifiers.xmss_mt encoding of the key, then
        // drop the BDS state. This exercises both the retained legacy read path - confirming keys
        // written by older releases still decode - and the no-BDS-state rebuild, which is only
        // reachable through the legacy form (the current default id-alg-xmssmt-hashsig encoding
        // always carries the BDS state inline).
        XMSSMTPrivateKeyParameters lwParams = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(pKey.getEncoded());
        byte[] raw = lwParams.getEncoded();                 // index || skSeed || skPRF || pubSeed || root || bds
        int headerLen = (20 + 7) / 8 + 4 * 32;              // indexSize + 4 * n  (n = 32 for SHA-256)
        byte[] bdsState = Arrays.copyOfRange(raw, headerLen, raw.length);
        org.bouncycastle.pqc.asn1.XMSSMTPrivateKey legacyKey = new org.bouncycastle.pqc.asn1.XMSSMTPrivateKey(
            lwParams.getIndex(), lwParams.getSecretKeySeed(), lwParams.getSecretKeyPRF(),
            lwParams.getPublicSeed(), lwParams.getRoot(), bdsState);
        AlgorithmIdentifier legacyAlg = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
            new XMSSMTKeyParams(20, 4, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)));

        ASN1Sequence seq = ASN1Sequence.getInstance(new PrivateKeyInfo(legacyAlg, legacyKey).parsePrivateKey());

        // create a new PrivateKeyInfo containing a key with no BDS state.
        PrivateKeyInfo pKeyInfo = new PrivateKeyInfo(legacyAlg,
            new DERSequence(new ASN1Encodable[]{seq.getObjectAt(0), seq.getObjectAt(1)}));

        XMSSMTPrivateKey privKey = (XMSSMTPrivateKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pKeyInfo.getEncoded()));

        assertEquals(privKey.getIndex(), pKey.getIndex());

        sig.initSign(pKey);

        sig.update(msg, 0, msg.length);

        byte[] sig1 = sig.sign();

        sig.initSign(privKey);

        sig.update(msg, 0, msg.length);

        byte[] sig2 = sig.sign();

        // make sure we get the same signature as the two keys should now
        // be in the same state.
        assertTrue(Arrays.areEqual(sig1, sig2));
    }

    public void testXMSSMTSha256KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 2, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTKey privKey = (XMSSMTKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
   
        assertEquals(kp.getPublic(), pubKey);

        assertEquals(20, privKey.getHeight());
        assertEquals(XMSSMTParameterSpec.SHA256, privKey.getTreeDigest());

        testSig("SHA256withXMSSMT", pubKey, (PrivateKey)privKey);
    }

    private void testSig(String algorithm, PublicKey pubKey, PrivateKey privKey)
        throws Exception
    {
        byte[] message = Strings.toByteArray("hello, world!");

        Signature s1 = Signature.getInstance(algorithm, "BCPQC");
        Signature s2 = Signature.getInstance(algorithm, "BCPQC");

        s1.initSign(privKey);

        for (int i = 0; i != 100; i++)
        {
            s1.update(message, 0, message.length);

            byte[] sig = s1.sign();

            s2.initVerify(pubKey);

            s2.update(message, 0, message.length);

            assertTrue(s2.verify(sig));
        }
    }

    public void testPrehashWithWithout()
        throws Exception
    {
        testPrehashAndWithoutPrehash("XMSSMT-SHA256", "SHA256", new SHA256Digest());
        testPrehashAndWithoutPrehash("XMSSMT-SHAKE128", "SHAKE128", new SHAKEDigest(128));
        testPrehashAndWithoutPrehash("XMSSMT-SHA512", "SHA512", new SHA512Digest());
        testPrehashAndWithoutPrehash("XMSSMT-SHAKE256", "SHAKE256", new SHAKEDigest(256));

        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHA256ph, BCObjectIdentifiers.xmss_mt_SHA256, "SHA256", new SHA256Digest());
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHAKE128ph, BCObjectIdentifiers.xmss_mt_SHAKE128, "SHAKE128", new SHAKEDigest(128));
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHAKE128_512ph, BCObjectIdentifiers.xmss_mt_SHAKE128, "SHAKE128", new DoubleDigest(new SHAKEDigest(128)));
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHA512ph, BCObjectIdentifiers.xmss_mt_SHA512, "SHA512", new SHA512Digest());
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHAKE256ph, BCObjectIdentifiers.xmss_mt_SHAKE256, "SHAKE256", new SHAKEDigest(256));
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHAKE256_1024ph, BCObjectIdentifiers.xmss_mt_SHAKE256, "SHAKE256", new DoubleDigest(new SHAKEDigest(256)));
    }

    public void testExhaustion()
        throws Exception
    {
        StateAwareSignature s1 = (StateAwareSignature)Signature.getInstance(BCObjectIdentifiers.xmss_mt_SHA256.getId(), "BCPQC");
        Signature s2 = Signature.getInstance(BCObjectIdentifiers.xmss_mt_SHA256.getId(), "BCPQC");

        byte[] message = Strings.toByteArray("hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, "SHA256"), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        XMSSMTPrivateKey privKey = (XMSSMTPrivateKey)kp.getPrivate();

        assertEquals(16, privKey.getUsagesRemaining());

        s1.initSign(privKey);

        do
        {
            s1.update(message, 0, message.length);

            byte[] sig = s1.sign();

            s2.initVerify(kp.getPublic());

            s2.update(message, 0, message.length);

            assertTrue(s2.verify(sig));

            privKey = (XMSSMTPrivateKey)s1.getUpdatedPrivateKey();

            s1.initSign(privKey);
        }
        while (s1.isSigningCapable());

        assertEquals(0, privKey.getUsagesRemaining());
    }

    public void testNoRepeats()
        throws Exception
    {
        byte[] message = Strings.toByteArray("hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, "SHA256"), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        XMSSMTPrivateKey privKey = (XMSSMTPrivateKey)kp.getPrivate();

        Signature sigGen = Signature.getInstance(BCObjectIdentifiers.xmss_mt_SHA256.getId(), "BCPQC");
        Signature sigVer = Signature.getInstance(BCObjectIdentifiers.xmss_mt_SHA256.getId(), "BCPQC");

        Set sigs = new HashSet();
        XMSSMTPrivateKey sigKey;
        while (privKey.getUsagesRemaining() != 0)
        {
            sigKey = privKey.extractKeyShard(privKey.getUsagesRemaining() > 4 ? 4 : (int)privKey.getUsagesRemaining());
            do
            {
                sigGen.initSign(sigKey);

                sigGen.update(message);

                byte[] sig = sigGen.sign();

                sigVer.initVerify(kp.getPublic());

                sigVer.update(message);

                PQCSigUtils.SigWrapper sw = new PQCSigUtils.SigWrapper(sig);

                if (sigs.contains(sw))
                {
                    fail("same sig generated twice");
                }
                sigs.add(sw);
            }
            while (sigKey.getUsagesRemaining() != 0);
        }

        kp = kpg.generateKeyPair();

        privKey = (XMSSMTPrivateKey)kp.getPrivate();

        sigs = new HashSet();

        sigGen.initSign(privKey);

        while (privKey.getUsagesRemaining() != 0)
        {

            sigGen.update(message);

            byte[] sig = sigGen.sign();

            sigVer.initVerify(kp.getPublic());

            sigVer.update(message);

            PQCSigUtils.SigWrapper sw = new PQCSigUtils.SigWrapper(sig);

            if (sigs.contains(sw))
            {
                fail("same sig generated twice");
            }
            sigs.add(sw);
        }

        try
        {
            privKey.getIndex();
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key exhausted", e.getMessage());
        }
    }

    private void testPrehashAndWithoutPrehash(String baseAlgorithm, String digestName, Digest digest)
        throws Exception
    {
        Signature s1 = Signature.getInstance(digestName + "with" + baseAlgorithm, "BCPQC");
        Signature s2 = Signature.getInstance(baseAlgorithm, "BCPQC");

        doTestPrehashAndWithoutPrehash(digestName, digest, s1, s2);
    }

    private void testPrehashAndWithoutPrehash(ASN1ObjectIdentifier oid1, ASN1ObjectIdentifier oid2, String digestName, Digest digest)
        throws Exception
    {
        Signature s1 = Signature.getInstance(oid1.getId(), "BCPQC");
        Signature s2 = Signature.getInstance(oid2.getId(), "BCPQC");

        doTestPrehashAndWithoutPrehash(digestName, digest, s1, s2);
    }

    private void doTestPrehashAndWithoutPrehash(String digestName, Digest digest, Signature s1, Signature s2)
        throws Exception
    {
        byte[] message = Strings.toByteArray("hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, digestName), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        s1.initSign(kp.getPrivate());

        s1.update(message, 0, message.length);

        byte[] sig = s1.sign();

        s2.initVerify(kp.getPublic());

        digest.update(message, 0, message.length);

        byte[] dig = new byte[digest.getDigestSize()];

        digest.doFinal(dig, 0);

        s2.update(dig);

        assertTrue(s2.verify(sig));
    }

    public void testShardedKeyExhaustion()
        throws Exception
    {
        Signature s1 = Signature.getInstance(BCObjectIdentifiers.xmss_mt_SHA256.getId(), "BCPQC");
        Signature s2 = Signature.getInstance(BCObjectIdentifiers.xmss_mt_SHA256.getId(), "BCPQC");

        byte[] message = Strings.toByteArray("hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        XMSSMTPrivateKey privKey = (XMSSMTPrivateKey)kp.getPrivate();

        assertEquals(16, privKey.getUsagesRemaining());

        XMSSMTPrivateKey extPrivKey = privKey.extractKeyShard(4);

        assertEquals(12, privKey.getUsagesRemaining());
        assertEquals(4, extPrivKey.getUsagesRemaining());

        exhaustKey(s1, s2, message, kp, extPrivKey, 4);

        assertEquals(12, privKey.getUsagesRemaining());

        extPrivKey = privKey.extractKeyShard(4);

        assertEquals(8, privKey.getUsagesRemaining());
        assertEquals(4, extPrivKey.getUsagesRemaining());

        exhaustKey(s1, s2, message, kp, extPrivKey, 4);

        assertEquals(8, privKey.getUsagesRemaining());

        exhaustKey(s1, s2, message, kp, privKey, 8);
    }

    private void exhaustKey(
        Signature s1, Signature s2, byte[] message, KeyPair kp, XMSSMTPrivateKey extPrivKey, int usages)
        throws GeneralSecurityException
    {
        // serialisation check
        assertEquals(extPrivKey.getUsagesRemaining(), usages);
        KeyFactory keyFact = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTPrivateKey pKey = (XMSSMTPrivateKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(extPrivKey.getEncoded()));

        assertEquals(usages, pKey.getUsagesRemaining());

        // usage check
        int count = 0;
        do
        {
            s1.initSign(extPrivKey);

            s1.update(message, 0, message.length);

            byte[] sig = s1.sign();

            s2.initVerify(kp.getPublic());

            s2.update(message, 0, message.length);

            assertTrue(s2.verify(sig));
            count++;
        }
        while (extPrivKey.getUsagesRemaining() != 0);

        assertEquals(usages, count);
        assertEquals(0, extPrivKey.getUsagesRemaining());
    }

    public void testReserialization()
        throws Exception
    {
        String digest = "SHA512";
        String sigAlg = digest + "withXMSSMT";
        byte[] payload = Strings.toByteArray("Hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
        kpg.initialize(new XMSSMTParameterSpec(4, 2, digest));
        KeyPair keyPair = kpg.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        for (int i = 0; i != 10; i++)
        {
            StateAwareSignature signer = (StateAwareSignature)Signature.getInstance(sigAlg, "BCPQC");
            signer.initSign(privateKey);
            signer.update(payload);

            byte[] signature = signer.sign();

            // serialise private key
            byte[] enc = signer.getUpdatedPrivateKey().getEncoded();
            privateKey = KeyFactory.getInstance("XMSSMT").generatePrivate(new PKCS8EncodedKeySpec(enc));

            Signature verifier = Signature.getInstance(sigAlg, "BCPQC");
            verifier.initVerify(publicKey);
            verifier.update(payload);
            assertTrue(verifier.verify(signature));
        }
    }

    static class DoubleDigest
        implements Digest
    {
        private SHAKEDigest digest;

        DoubleDigest(SHAKEDigest digest)
        {
             this.digest = digest;
        }

        @Override
        public String getAlgorithmName()
        {
            return digest.getAlgorithmName() + "/" + (digest.getDigestSize() * 2 * 8);
        }

        @Override
        public int getDigestSize()
        {
            return digest.getDigestSize() * 2;
        }

        @Override
        public void update(byte in)
        {
             digest.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            digest.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            return digest.doFinal(out, outOff, this.getDigestSize());
        }

        @Override
        public void reset()
        {
            digest.reset();
        }
    }
}
