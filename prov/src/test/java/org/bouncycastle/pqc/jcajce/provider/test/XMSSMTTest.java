package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
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

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
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

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT-SHA256", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        assertTrue(xmssSig.isSigningCapable());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        PrivateKey nKey = xmssSig.getUpdatedPrivateKey();

        assertFalse(kp.getPrivate().equals(nKey));
        assertFalse(xmssSig.isSigningCapable());

        xmssSig.update(msg, 0, msg.length);

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
            xmssSig.getUpdatedPrivateKey();
            fail("no exception after key extraction");
        }
        catch (IllegalStateException e)
        {
            assertEquals("signature object not in a signing state", e.getMessage());
        }

        xmssSig.initSign(nKey);

        xmssSig.update(msg, 0, msg.length);

        s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
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
        assertEquals(XMSSParameterSpec.SHA512, privKey.getTreeDigest());

        assertEquals(20, pubKey.getHeight());
        assertEquals(10, pubKey.getLayers());
        assertEquals(XMSSParameterSpec.SHA512, pubKey.getTreeDigest());
    }

    public void testXMSSMTSha256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(10, 5, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSMTSha512Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(10, 5, XMSSMTParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSMTShake128Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE128), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHAKE128withXMSSMT-SHAKE128", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSMTShake256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHAKE256withXMSSMT-SHAKE256", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testKeyRebuild()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(6, 3, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        for (int i = 0; i != 5; i++)
        {
            xmssSig.update(msg, 0, msg.length);

            xmssSig.sign();
        }

        PrivateKey pKey = xmssSig.getUpdatedPrivateKey();

        PrivateKeyInfo pKeyInfo = PrivateKeyInfo.getInstance(pKey.getEncoded());

        KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");

        ASN1Sequence seq = ASN1Sequence.getInstance(pKeyInfo.parsePrivateKey());

        // create a new PrivateKeyInfo containing a key with no BDS state.
        pKeyInfo = new PrivateKeyInfo(pKeyInfo.getPrivateKeyAlgorithm(),
            new DERSequence(new ASN1Encodable[] { seq.getObjectAt(0), seq.getObjectAt(1) }));

        XMSSMTKey privKey = (XMSSMTKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pKeyInfo.getEncoded()));

        xmssSig.initSign(pKey);

        xmssSig.update(msg, 0, msg.length);

        byte[] sig1 = xmssSig.sign();

        xmssSig.initSign((PrivateKey)privKey);

        xmssSig.update(msg, 0, msg.length);

        byte[] sig2 = xmssSig.sign();

        // make sure we get the same signature as the two keys should now
        // be in the same state.
        assertTrue(Arrays.areEqual(sig1, sig2));
    }

    public void testXMSSMTSha256KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(10, 2, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTKey privKey = (XMSSMTKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(10, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHA256, privKey.getTreeDigest());

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
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHA512ph, BCObjectIdentifiers.xmss_mt_SHA512, "SHA512", new SHA512Digest());
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_mt_SHAKE256ph, BCObjectIdentifiers.xmss_mt_SHAKE256, "SHAKE256", new SHAKEDigest(256));
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

        byte[] dig = new byte[(digest instanceof Xof) ? digest.getDigestSize() * 2 : digest.getDigestSize()];

        if (digest instanceof Xof)
        {
            ((Xof)digest).doFinal(dig, 0, dig.length);
        }
        else
        {
            digest.doFinal(dig, 0);
        }
        s2.update(dig);

        assertTrue(s2.verify(sig));
    }
}
