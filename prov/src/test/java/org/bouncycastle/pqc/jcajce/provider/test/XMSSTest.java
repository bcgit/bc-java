package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
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
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

/**
 * Test cases for the use of XMSS with the BCPQC provider.
 */
public class XMSSTest
    extends TestCase
{
    private static byte[] msg = Strings.toByteArray("Cthulhu Fthagn --What a wonderful phrase!Cthulhu Fthagn --Say it and you're crazed!");

    private static byte[] testPrivKey = Base64.decode(
        "MIIJUQIBADAhBgorBgEEAYGwGgICMBMCAQACAQowCwYJYIZIAWUDBAIBBIIJJzCCCSMCAQAwgYsCAQAEIJz4Lh9eEhuxG4dgjfRXOw" +
            "K7Um5YmC6Xf4lkXvtPgsdnBCDNR477ikIt1sOIr3+ElyurEY2gvVYydvk+LZm+OY/pagQgwCnFSoMAerORUDoJHb9tXqrCzIp52yYz" +
            "gr3TOIKhzcAEIOCommSN0UszkpJUMLzJxe856LQbH7hl73xPpFnCwVJtoIIIjgSCCIqs7QAFc3IAJG9yZy5ib3VuY3ljYXN0bGUucH" +
            "FjLmNyeXB0by54bXNzLkJEUwAAAAAAAAABAgAKSQAFaW5kZXhJAAFrSQAKdHJlZUhlaWdodFoABHVzZWRMABJhdXRoZW50aWNhdGlv" +
            "blBhdGh0ABBMamF2YS91dGlsL0xpc3Q7TAAEa2VlcHQAD0xqYXZhL3V0aWwvTWFwO0wABnJldGFpbnEAfgACTAAEcm9vdHQAK0xvcm" +
            "cvYm91bmN5Y2FzdGxlL3BxYy9jcnlwdG8veG1zcy9YTVNTTm9kZTtMAAVzdGFja3QAEUxqYXZhL3V0aWwvU3RhY2s7TAARdHJlZUhh" +
            "c2hJbnN0YW5jZXNxAH4AAXhwAAAAAAAAAAIAAAAKAHNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAA" +
            "AKdwQAAAAKc3IAKW9yZy5ib3VuY3ljYXN0bGUucHFjLmNyeXB0by54bXNzLlhNU1NOb2RlAAAAAAAAAAECAAJJAAZoZWlnaHRbAAV2" +
            "YWx1ZXQAAltCeHAAAAAAdXIAAltCrPMX+AYIVOACAAB4cAAAACAGQv71vuxiZWXV4/Ju/9iKZCWJJH/tGib2csoUJOc8eHNxAH4ACA" +
            "AAAAF1cQB+AAsAAAAgsqaSHpyaapwnlBv57C8sKLYUAp3Oe8jY2EZ8hSA7VQVzcQB+AAgAAAACdXEAfgALAAAAIL5Eb9aOASc8bJNt" +
            "AwbO7pmTD7rMl74XiufBHOqgjXR+c3EAfgAIAAAAA3VxAH4ACwAAACDDX+WyjGU4eUb5OvHYbjVsjUAPHSSGRCfhC8BmTMD8gXNxAH" +
            "4ACAAAAAR1cQB+AAsAAAAgxdz9x1wcJzZuwWSubFsFwD6IICfG+nj2kRbZtGP0LvlzcQB+AAgAAAAFdXEAfgALAAAAINrZJ2N7sn7i" +
            "mddC8uuL3kwvsem8S/HLNVvFdu7mDjUVc3EAfgAIAAAABnVxAH4ACwAAACAnH0jqcIwZ43zMTbOz5l/SPBYA8I2G3ThJxyK3+CFqX3" +
            "NxAH4ACAAAAAd1cQB+AAsAAAAgUesW9Krrb+DRkRfvw1GedWY2mkicW9gWysuxdpcwQpJzcQB+AAgAAAAIdXEAfgALAAAAILTstGe7" +
            "7ZTz+Tu9hXo6W6Ceek8iqoMWR2LnlB4MlHDNc3EAfgAIAAAACXVxAH4ACwAAACBcak0jZQNXH/RqUaXXchab6lVlt0tFPwjDyjA6zj" +
            "yigHhzcgARamF2YS51dGlsLlRyZWVNYXAMwfY+LSVq5gMAAUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHBw" +
            "dwQAAAAAeHNxAH4AH3B3BAAAAAFzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW" +
            "1iZXKGrJUdC5TgiwIAAHhwAAAACHNyABRqYXZhLnV0aWwuTGlua2VkTGlzdAwpU11KYIgiAwAAeHB3BAAAAAFzcQB+AAgAAAAIdXEA" +
            "fgALAAAAINAd+MxJvrqmIxJYJvpW7TJZBtAw8xVVrWffg0v/FqNgeHhzcQB+AAgAAAAKdXEAfgALAAAAIOCommSN0UszkpJUMLzJxe" +
            "856LQbH7hl73xPpFnCwVJtc3IAD2phdmEudXRpbC5TdGFjaxD+KsK7CYYdAgAAeHIAEGphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMA" +
            "A0kAEWNhcGFjaXR5SW5jcmVtZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHAAAA" +
            "AAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAApwcHBwcHBwcHBweHNxAH4ABgAAAAh3BAAAAAhzcgAs" +
            "b3JnLmJvdW5jeWNhc3RsZS5wcWMuY3J5cHRvLnhtc3MuQkRTVHJlZUhhc2gAAAAAAAAAAQIABloACGZpbmlzaGVkSQAGaGVpZ2h0SQ" +
            "ANaW5pdGlhbEhlaWdodFoAC2luaXRpYWxpemVkSQAJbmV4dEluZGV4TAAIdGFpbE5vZGVxAH4AA3hwAQAAAAAAAAAAAAAAAABzcQB+" +
            "AAgAAAAAdXEAfgALAAAAIJlIeq2/6feYEOIoFJ14wZsogn4eAI7kNj3Y4NZtAGY0c3EAfgAzAQAAAAEAAAABAAAAAABzcQB+AAgAAA" +
            "ABdXEAfgALAAAAIO5nPo5M/pLgkDLgzkCTUy+VjaPEo3cgMm5Mrg11jKXoc3EAfgAzAQAAAAIAAAACAAAAAABzcQB+AAgAAAACdXEA" +
            "fgALAAAAIKGPe8aqDKAN6p7i5wpnVgBr+wigNp8CRKtJI1FjDgnLc3EAfgAzAQAAAAMAAAADAAAAAABzcQB+AAgAAAADdXEAfgALAA" +
            "AAIEFdO93VUT6Q6tt4ZJaVf+Uh3BJ7ez9megbGCGEvjD1Sc3EAfgAzAQAAAAQAAAAEAAAAAABzcQB+AAgAAAAEdXEAfgALAAAAIGkP" +
            "gbAYQss69U6Ak7S2yciX1cnj+9C3KjFh5j5pILQoc3EAfgAzAQAAAAUAAAAFAAAAAABzcQB+AAgAAAAFdXEAfgALAAAAICZR+aZttx" +
            "PqjHYIQlaFac2mK5WiEiSy8Je+XmItQ6Xac3EAfgAzAQAAAAYAAAAGAAAAAABzcQB+AAgAAAAGdXEAfgALAAAAINoMTeI/1jvR+IIh" +
            "yA+vQ0xR9/8utcwXpV+hT/qkVNtCc3EAfgAzAQAAAAcAAAAHAAAAAABzcQB+AAgAAAAHdXEAfgALAAAAIFmxQ2yQ05Na9oL4WA2Qhp" +
            "qICwl81rpce4LFUAtTdj95eA==");

    private static final byte[] testPublicKey = Base64.decode(
        "MIGxMCEGCisGAQQBgbAaAgIwEwIBAAIBCjALBglghkgBZQMEAgMDgYsAMIGHAgEABEDcKHL+5XfQ9jTGJptcqN71MmzT1qe/s42wwR" +
            "6TkILd1jH6e5vP9Iwp+hANEWJdbxYX4gyyQQpudfOQ6+7xLJNaBEAmGsvLXJAJXu5NTICpC5LpKrWWxrz6tKRiLP10EBbxtLwM3wCW" +
            "6+d4CehmSP7B0ffx6AzJtD6l6T+lxyO0EMXG");

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
        KeyFactory kFact = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(priv160Pkcs8));

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(priv160Ser));

        XMSSKey privKey2 = (XMSSKey)oIn.readObject();

        assertEquals(privKey, privKey2);
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(testPrivKey));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        XMSSKey privKey2 = (XMSSKey)oIn.readObject();

        assertEquals(privKey, privKey2);
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey pubKey = (XMSSKey)kFact.generatePublic(new X509EncodedKeySpec(testPublicKey));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        XMSSKey pubKey2 = (XMSSKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
    }

    public void testXMSSSha256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature xmssSig = Signature.getInstance("SHA256withXMSS", "BCPQC");

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = xmssSig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSSha512Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature xmssSig = Signature.getInstance("SHA512withXMSS", "BCPQC");

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = xmssSig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSShake128Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(5, XMSSParameterSpec.SHAKE128), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature xmssSig = Signature.getInstance("SHAKE128withXMSS", "BCPQC");

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = xmssSig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSShake256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(5, XMSSParameterSpec.SHAKE256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature xmssSig = Signature.getInstance("SHAKE256withXMSS", "BCPQC");

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = xmssSig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSSha256SignatureMultiplePreHash()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig1 = Signature.getInstance("SHA256withXMSS", "BCPQC");

        Signature sig2 = Signature.getInstance("SHA256withXMSS", "BCPQC");

        Signature sig3 = Signature.getInstance("SHA256withXMSS", "BCPQC");

        XMSSPrivateKey xmsPrivKey = (XMSSPrivateKey)kp.getPrivate();

        sig1.initSign(xmsPrivKey.extractKeyShard(1));

        sig2.initSign(xmsPrivKey.extractKeyShard(1));

        sig3.initSign(xmsPrivKey.extractKeyShard(1));

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

    public void testXMSSSha256KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(XMSSParameterSpec.SHA2_10_256, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(10, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHA256, privKey.getTreeDigest());

        testSig("XMSS", pubKey, (PrivateKey)privKey);
    }

    public void testXMSSSha512KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSKey pubKey = (XMSSKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(10, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHA512, privKey.getTreeDigest());

        assertEquals(10, pubKey.getHeight());
        assertEquals(XMSSParameterSpec.SHA512, pubKey.getTreeDigest());
    }

    public void testXMSSShake128KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHAKE128), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSKey pubKey = (XMSSKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(10, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHAKE128, privKey.getTreeDigest());

        assertEquals(10, pubKey.getHeight());
        assertEquals(XMSSParameterSpec.SHAKE128, pubKey.getTreeDigest());
    }

    public void testXMSSShake256KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHAKE256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSKey pubKey = (XMSSKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(10, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHAKE256, privKey.getTreeDigest());

        assertEquals(10, pubKey.getHeight());
        assertEquals(XMSSParameterSpec.SHAKE256, pubKey.getTreeDigest());
    }

    private void testSig(String algorithm, PublicKey pubKey, PrivateKey privKey)
        throws Exception
    {
        byte[] message = Strings.toByteArray("hello, world!");

        Signature s = Signature.getInstance(algorithm, "BCPQC");

        s.initSign(privKey);

        s.update(message, 0, message.length);

        byte[] sig = s.sign();

        s.initVerify(pubKey);

        s.update(message, 0, message.length);

        assertTrue(s.verify(sig));
    }

    public void testKeyExtraction()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSS", "BCPQC");

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        assertTrue(xmssSig.isSigningCapable());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = xmssSig.sign();

        PrivateKey nKey = xmssSig.getUpdatedPrivateKey();

        assertTrue(kp.getPrivate().equals(nKey));
        assertFalse(xmssSig.isSigningCapable());

        xmssSig.update(msg, 0, msg.length);

        try
        {
            xmssSig.sign();
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

    public void testKeyRebuild()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSS", "BCPQC");

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

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        ASN1Sequence seq = ASN1Sequence.getInstance(pKeyInfo.parsePrivateKey());

        // create a new PrivateKeyInfo containing a key with no BDS state.
        pKeyInfo = new PrivateKeyInfo(pKeyInfo.getPrivateKeyAlgorithm(),
            new DERSequence(new ASN1Encodable[]{seq.getObjectAt(0), seq.getObjectAt(1)}));

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pKeyInfo.getEncoded()));

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

    public void testPrehashWithWithout()
        throws Exception
    {
        testPrehashAndWithoutPrehash("XMSS-SHA256", "SHA256", new SHA256Digest());
        testPrehashAndWithoutPrehash("XMSS-SHAKE128", "SHAKE128", new SHAKEDigest(128));
        testPrehashAndWithoutPrehash("XMSS-SHA512", "SHA512", new SHA512Digest());
        testPrehashAndWithoutPrehash("XMSS-SHAKE256", "SHAKE256", new SHAKEDigest(256));

        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHA256ph, BCObjectIdentifiers.xmss_SHA256, "SHA256", new SHA256Digest());
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHAKE128ph, BCObjectIdentifiers.xmss_SHAKE128, "SHAKE128", new SHAKEDigest(128));
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHA512ph, BCObjectIdentifiers.xmss_SHA512, "SHA512", new SHA512Digest());
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHAKE256ph, BCObjectIdentifiers.xmss_SHAKE256, "SHAKE256", new SHAKEDigest(256));
    }

    public void testExhaustion()
        throws Exception
    {
        StateAwareSignature s1 = (StateAwareSignature)Signature.getInstance(BCObjectIdentifiers.xmss_SHA256.getId(), "BCPQC");
        Signature s2 = Signature.getInstance(BCObjectIdentifiers.xmss_SHA256.getId(), "BCPQC");

        byte[] message = Strings.toByteArray("hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(2, "SHA256"), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        XMSSPrivateKey privKey = (XMSSPrivateKey)kp.getPrivate();

        assertEquals(4, privKey.getUsagesRemaining());

        s1.initSign(privKey);
        
        do
        {
            s1.update(message, 0, message.length);

            byte[] sig = s1.sign();

            s2.initVerify(kp.getPublic());

            s2.update(message, 0, message.length);

            assertTrue(s2.verify(sig));

            privKey = (XMSSPrivateKey)s1.getUpdatedPrivateKey();

            s1.initSign(privKey);
        }
        while (s1.isSigningCapable());

        assertEquals(0, privKey.getUsagesRemaining());
    }

    public void testShardedKeyExhaustion()
        throws Exception
    {
        Signature s1 = Signature.getInstance(BCObjectIdentifiers.xmss_SHA256.getId(), "BCPQC");
        Signature s2 = Signature.getInstance(BCObjectIdentifiers.xmss_SHA256.getId(), "BCPQC");

        byte[] message = Strings.toByteArray("hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, "SHA256"), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        XMSSPrivateKey privKey = (XMSSPrivateKey)kp.getPrivate();

        assertEquals(16, privKey.getUsagesRemaining());

        XMSSPrivateKey extPrivKey = privKey.extractKeyShard(4);

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
        Signature s1, Signature s2, byte[] message, KeyPair kp, XMSSPrivateKey extPrivKey, int usages)
        throws GeneralSecurityException
    {
        // serialisation check
        assertEquals(extPrivKey.getUsagesRemaining(), usages);
        KeyFactory keyFact = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSPrivateKey pKey = (XMSSPrivateKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(extPrivKey.getEncoded()));

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

    public void testNoRepeats()
        throws Exception
    {
        byte[] message = Strings.toByteArray("hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, "SHA256"), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        XMSSPrivateKey privKey = (XMSSPrivateKey)kp.getPrivate();

        Signature sigGen = Signature.getInstance(BCObjectIdentifiers.xmss_SHA256.getId(), "BCPQC");
        Signature sigVer = Signature.getInstance(BCObjectIdentifiers.xmss_SHA256.getId(), "BCPQC");

        Set sigs = new HashSet();
        XMSSPrivateKey sigKey;
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

        privKey = (XMSSPrivateKey)kp.getPrivate();

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

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(2, digestName), new SecureRandom());

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

    public void testReserialization()
        throws Exception
    {
        String digest = "SHA512";
        String sigAlg = digest + "withXMSS";
        byte[] payload = Strings.toByteArray("Hello, world!");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        kpg.initialize(new XMSSParameterSpec(4, digest));
        KeyPair keyPair = kpg.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        for (int i = 0; i != 10; i++)
        {
            Signature signer = Signature.getInstance(sigAlg, "BCPQC");
            signer.initSign(privateKey);
            signer.update(payload);

            byte[] signature = signer.sign();

            // serialise private key
            byte[] enc = privateKey.getEncoded();
            privateKey = KeyFactory.getInstance("XMSS").generatePrivate(new PKCS8EncodedKeySpec(enc));
            Signature verifier = Signature.getInstance(sigAlg, "BCPQC");
            verifier.initVerify(publicKey);
            verifier.update(payload);
            assertTrue(verifier.verify(signature));
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privateKey);
        oOut.writeObject(privateKey);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        oIn.readObject();
        oIn.readObject();
    }
}
