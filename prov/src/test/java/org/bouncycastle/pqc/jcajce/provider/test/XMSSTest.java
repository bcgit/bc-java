package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
import org.bouncycastle.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.jcajce.provider.asymmetric.xmss.BCXMSSPrivateKey;
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

    /**
     * A private key written by a release before the XMSS implementation was promoted out of
     * org.bouncycastle.pqc.crypto.xmss carries its BDS traversal state as a Java serialized graph
     * naming the classes of that package. The promoted reader has to go on accepting it, which it
     * does by mapping those four class names onto the classes in
     * org.bouncycastle.crypto.signers.xmss - nothing writes them any more, so only a fixture like
     * this one exercises the path.
     */
    public void testPromotedFactoryReadsLegacyBdsState()
        throws Exception
    {
        assertTrue("fixture is not a pre-promotion key", XMSSTestUtils.hasLegacyBdsMarker(testPrivKey));

        AsymmetricKeyParameter key = org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(testPrivKey);

        assertTrue(key instanceof org.bouncycastle.crypto.params.XMSSPrivateKeyParameters);
    }

    /**
     * XMSS is now a BC provider algorithm as well as a BCPQC one - the BC provider has carried
     * the key info converters for it for some time, but the KeyFactory, KeyPairGenerator and
     * Signature services were only in BCPQC.
     */
    public void testBCProviderServices()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("XMSS-SHA256", "BC");

        sig.initSign(kp.getPrivate());
        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        KeyFactory kFact = KeyFactory.getInstance("XMSS", "BC");

        assertEquals(kp.getPublic(), kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
        assertEquals(kp.getPrivate(), kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded())));

        // the same key must go back and forth between the two providers
        assertEquals(kp.getPublic(),
            KeyFactory.getInstance("XMSS", "BCPQC").generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
    }

    public void test160PrivateKeyRecovery()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(priv160Pkcs8));

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(priv160Ser));

        XMSSKey privKey2 = (XMSSKey)oIn.readObject();

        // the stored stream names the pre-promotion org.bouncycastle.pqc.jcajce.provider.xmss class, so what
        // comes back is of that class rather than the one the provider builds now, and each class's equals()
        // requires its own type - the key material is what this test is about.
        assertTrue(org.bouncycastle.util.Arrays.areEqual(
            ((java.security.Key)privKey).getEncoded(), ((java.security.Key)privKey2).getEncoded()));
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

    public void testRFC9802PublicKeyEncoding()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        // RFC 9802: id-alg-xmss-hashsig, absent parameters, raw RFC 8391 key in the BIT STRING.
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        assertEquals(IANAObjectIdentifiers.id_alg_xmss_hashsig, keyInfo.getAlgorithm().getAlgorithm());
        assertNull(keyInfo.getAlgorithm().getParameters());

        byte[] rawKey = keyInfo.getPublicKeyData().getOctets();

        KeyFactory kFact = KeyFactory.getInstance("XMSS", "BCPQC");

        PublicKey pubKey = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        // the legacy draft form - id_alg_xmss with the key wrapped in an OCTET STRING - must still decode.
        SubjectPublicKeyInfo legacy = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmss), new DEROctetString(rawKey));

        PublicKey legacyKey = kFact.generatePublic(new X509EncodedKeySpec(legacy.getEncoded()));

        assertEquals(kp.getPublic(), legacyKey);
    }

    public void testSP800208KeyGenAndRoundTrip()
        throws Exception
    {
        String[] treeDigests = {
            XMSSParameterSpec.SHA256_192, XMSSParameterSpec.SHAKE256_256, XMSSParameterSpec.SHAKE256_192};

        for (int i = 0; i != treeDigests.length; i++)
        {
            String treeDigest = treeDigests[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
            kpg.initialize(new XMSSParameterSpec(10, treeDigest), new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            // private and public halves share the RFC 9802 algorithm OID
            assertEquals(treeDigest, IANAObjectIdentifiers.id_alg_xmss_hashsig,
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
            assertEquals(treeDigest, IANAObjectIdentifiers.id_alg_xmss_hashsig,
                PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded()).getPrivateKeyAlgorithm().getAlgorithm());

            // getTreeDigest() reflects the specific SP 800-208 variant (n included)
            assertEquals(treeDigest, ((XMSSKey)kp.getPublic()).getTreeDigest());
            assertEquals(treeDigest, ((XMSSKey)kp.getPrivate()).getTreeDigest());

            // KeyFactory round-trips both halves to equal keys
            KeyFactory kFact = KeyFactory.getInstance("XMSS", "BCPQC");
            PublicKey pubKey = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey privKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            assertEquals(treeDigest, kp.getPublic(), pubKey);
            assertEquals(treeDigest, kp.getPrivate(), privKey);

            // the generated key signs and verifies
            Signature xmssSig = Signature.getInstance("XMSS", "BCPQC");
            xmssSig.initSign(kp.getPrivate());
            xmssSig.update(msg, 0, msg.length);
            byte[] s = xmssSig.sign();
            xmssSig.initVerify(kp.getPublic());
            xmssSig.update(msg, 0, msg.length);
            assertTrue(treeDigest, xmssSig.verify(s));
        }
    }

    /**
     * An XMSS signature is the fixed-size encoding of RFC 8391 sec. 4.1.8, so a valid signature
     * carrying trailing data is not a signature - XMSS used to read its fields at their fixed
     * offsets and ignore the tail, where XMSS^MT already checked the total length (github #2408).
     */
    public void testSignatureWithTrailingBytesRejected()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("XMSS-SHA256", "BCPQC");

        signer.initSign(kp.getPrivate());
        signer.update(msg, 0, msg.length);

        byte[] sig = signer.sign();

        signer.initVerify(kp.getPublic());
        signer.update(msg, 0, msg.length);

        assertTrue(signer.verify(sig));

        signer.initVerify(kp.getPublic());
        signer.update(msg, 0, msg.length);

        assertFalse("signature with trailing data accepted", signer.verify(Arrays.append(sig, (byte)0x2a)));

        signer.initVerify(kp.getPublic());
        signer.update(msg, 0, msg.length);

        assertFalse("truncated signature accepted", signer.verify(Arrays.copyOfRange(sig, 0, sig.length - 1)));
    }

    /**
     * A key spec the factory cannot decode is reported with what went wrong attached, as the LMS
     * key factory beside it does - the XMSS and XMSS^MT ones folded the underlying exception into
     * their own message text and dropped it, leaving a caller walking getCause() with nothing.
     */
    public void testKeyFactoryReportsTheCause()
        throws Exception
    {
        String[] algorithms = new String[]{"XMSS", "XMSSMT"};

        for (int i = 0; i != algorithms.length; i++)
        {
            KeyFactory kFact = KeyFactory.getInstance(algorithms[i], "BCPQC");

            try
            {
                kFact.generatePrivate(new PKCS8EncodedKeySpec(new byte[]{0x30, 0x01, 0x00}));
                fail("malformed private key spec accepted");
            }
            catch (InvalidKeySpecException e)
            {
                assertNotNull(algorithms[i] + " private key spec cause dropped", e.getCause());
            }

            try
            {
                kFact.generatePublic(new X509EncodedKeySpec(new byte[]{0x30, 0x01, 0x00}));
                fail("malformed public key spec accepted");
            }
            catch (InvalidKeySpecException e)
            {
                assertNotNull(algorithms[i] + " public key spec cause dropped", e.getCause());
            }
        }
    }

    /**
     * generateKeyPair() without a preceding initialize() has to produce a usable key - one whose
     * tree digest is set, so equals()/hashCode()/getTreeDigest() work on it (github #2408).
     */
    public void testDefaultKeyPairGeneration()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("XMSS", "BCPQC").generateKeyPair();

        XMSSKey pubKey = (XMSSKey)kp.getPublic();

        assertEquals(10, pubKey.getHeight());
        assertEquals(XMSSParameterSpec.SHA512, pubKey.getTreeDigest());
        assertEquals(kp.getPublic(), kp.getPublic());
        assertEquals(kp.getPublic().hashCode(), kp.getPublic().hashCode());

        KeyFactory kFact = KeyFactory.getInstance("XMSS", "BCPQC");

        assertEquals(kp.getPublic(), kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));

        Signature signer = Signature.getInstance("XMSS", "BCPQC");

        signer.initSign(kp.getPrivate());
        signer.update(msg, 0, msg.length);

        byte[] sig = signer.sign();

        signer.initVerify(kp.getPublic());
        signer.update(msg, 0, msg.length);

        assertTrue(signer.verify(sig));
    }

    public void testSignerKeyDigestFamilyEnforcement()
        throws Exception
    {
        KeyPairGenerator shaKpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        shaKpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());
        KeyPair shaKp = shaKpg.generateKeyPair();

        KeyPairGenerator shakeKpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        shakeKpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHAKE256), new SecureRandom());
        KeyPair shakeKp = shakeKpg.generateKeyPair();

        // a SHA256 key handed to a SHAKE256-named signer is rejected on both init paths
        Signature shakeSig = Signature.getInstance("XMSS-SHAKE256", "BCPQC");
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
        Signature shaSig = Signature.getInstance("XMSS-SHA256", "BCPQC");
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

        // the generic "XMSS" signer is lenient - it accepts any key
        Signature genericSig = Signature.getInstance("XMSS", "BCPQC");
        genericSig.initSign(shaKp.getPrivate());
        genericSig.update(msg, 0, msg.length);
        byte[] gs = genericSig.sign();
        genericSig.initVerify(shaKp.getPublic());
        genericSig.update(msg, 0, msg.length);
        assertTrue(genericSig.verify(gs));

        // SP 800-208 SHAKE256/256 keys (tree digest id-shake256-len) are within the SHAKE256 family
        KeyPairGenerator sp800Kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        sp800Kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHAKE256_256), new SecureRandom());
        KeyPair sp800Kp = sp800Kpg.generateKeyPair();

        Signature sp800Sig = Signature.getInstance("XMSS-SHAKE256", "BCPQC");
        sp800Sig.initSign(sp800Kp.getPrivate());
        sp800Sig.update(msg, 0, msg.length);
        byte[] sp = sp800Sig.sign();
        sp800Sig.initVerify(sp800Kp.getPublic());
        sp800Sig.update(msg, 0, msg.length);
        assertTrue(sp800Sig.verify(sp));

        // and SHA-256/192 keys are within the SHA256 family
        KeyPairGenerator sha192Kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        sha192Kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256_192), new SecureRandom());
        KeyPair sha192Kp = sha192Kpg.generateKeyPair();

        Signature sha192Sig = Signature.getInstance("XMSS-SHA256", "BCPQC");
        sha192Sig.initSign(sha192Kp.getPrivate());
        sha192Sig.update(msg, 0, msg.length);
        byte[] sh = sha192Sig.sign();
        sha192Sig.initVerify(sha192Kp.getPublic());
        sha192Sig.update(msg, 0, msg.length);
        assertTrue(sha192Sig.verify(sh));
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

    /**
     * initSign(PrivateKey, SecureRandom) is the two-argument JCA form, and it is the one that goes
     * through XMSSSignatureSpi.engineInitSign(PrivateKey, SecureRandom): that wraps the key in a
     * ParametersWithRandom before handing it to the signer. XMSS derives its randomizer from the
     * key itself (RFC 8391 sec. 4.1.9), so the supplied SecureRandom is discarded - but the wrapper
     * still has to be accepted, and used to raise a ClassCastException out of initSign. Every
     * other test here uses the one-argument form, which does not wrap.
     */
    public void testInitSignWithSecureRandom()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(5, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("XMSS", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        // and the one-argument form on the same object afterwards, which is now the other branch
        // rather than the same one: the SPI used to hold the random in a field, so a second init
        // without one wrapped the key again with what the first had left behind, and this was that
        // sticky path. The random is a method argument now and the second init passes null, so what
        // this asserts is that the two forms are interchangeable on one Signature object - the
        // unwrapped key after the wrapped one, on a signer that has already signed and verified.
        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] s2 = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s2));
    }

    public void testXMSSSha256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(5, XMSSParameterSpec.SHA256), new SecureRandom());

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

        kpg.initialize(new XMSSParameterSpec(5, XMSSParameterSpec.SHA512), new SecureRandom());

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

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

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

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSKey pubKey = (XMSSKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(4, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHA512, privKey.getTreeDigest());

        assertEquals(4, pubKey.getHeight());
        assertEquals(XMSSParameterSpec.SHA512, pubKey.getTreeDigest());
    }

    public void testXMSSShake128KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHAKE128), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSKey pubKey = (XMSSKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(4, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHAKE128, privKey.getTreeDigest());

        assertEquals(4, pubKey.getHeight());
        assertEquals(XMSSParameterSpec.SHAKE128, pubKey.getTreeDigest());
    }

    public void testXMSSShake256KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHAKE256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSKey pubKey = (XMSSKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(4, privKey.getHeight());
        assertEquals(XMSSParameterSpec.SHAKE256, privKey.getTreeDigest());

        assertEquals(4, pubKey.getHeight());
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

    /**
     * equals() answers on the whole key, including the traversal state it is sitting on, and the
     * fields it looks at before re-encoding anything are a shortcut to that answer rather than a
     * different one. So: the same key twice is equal, a key round-tripped through its encoding is
     * equal to what it came from, a key that has signed and moved on is not equal to the key it
     * was, and two key pairs are not equal to each other at the same index.
     * <p>
     * hashCode() is asserted beside it, because the two are one contract and because both are now
     * the key parameters' - this class delegates each in a line, the way BCLMSPrivateKey does to
     * HSSPrivateKeyParameters. Equal keys hash the same, and a key that has signed keeps the hash
     * it had: hashCode() is over the fields that do not move, so keys from one key pair share a
     * bucket and equals() tells them apart inside it. A key lost from a Set by signing is what the
     * other way round would cost.
     * </p>
     */
    public void testXMSSPrivateKeyEquality()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("XMSS", "BCPQC");

        // a key of its own, so that signing with kp's does not move this one too
        PrivateKey atZero = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(atZero, atZero);
        assertEquals(kp.getPrivate(), atZero);
        assertEquals(atZero, kf.generatePrivate(new PKCS8EncodedKeySpec(atZero.getEncoded())));
        assertEquals("equal keys hash differently",
            kp.getPrivate().hashCode(), atZero.hashCode());

        StateAwareSignature sig =
            (StateAwareSignature)Signature.getInstance("SHA256withXMSS", "BCPQC");

        sig.initSign(kp.getPrivate());
        sig.update(msg, 0, msg.length);
        sig.sign();

        PrivateKey atOne = sig.getUpdatedPrivateKey();

        assertFalse("a key that has signed equals the key it was", atZero.equals(atOne));
        assertFalse("a key that has signed equals the key it was", atOne.equals(atZero));
        assertEquals("a key that has signed changed bucket", atZero.hashCode(), atOne.hashCode());

        PrivateKey other = kf.generatePrivate(
            new PKCS8EncodedKeySpec(kpg.generateKeyPair().getPrivate().getEncoded()));

        assertFalse("two key pairs are equal at the same index", atZero.equals(other));
        assertFalse("two key pairs are equal at the same index", other.equals(atZero));
    }

    /**
     * Two private keys alike in everything the key's encoding holds except one of the two secrets.
     * <p>
     * equals() answers on the fields ahead of the traversal state and then on the state itself, so
     * those field comparisons have to reach both seeds. secretKeyPRF is the one that shows it: it
     * takes no part in the root or in the traversal state - it keys the randomizer r of RFC 8391
     * sec. 4.1.9, which travels in the signature - so two keys differing only in it agree on
     * everything else a key exposes while producing a different signature for every message.
     * </p>
     */
    public void testXMSSPrivateKeysDifferingOnlyInASecretAreNotEqual()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        PrivateKey base = keyHolding(params, 1, 2);

        assertEquals("the same fields twice are not equal", base, keyHolding(params, 1, 2));
        assertFalse("keys differing only in secretKeyPRF are equal",
            base.equals(keyHolding(params, 1, 99)));
        assertFalse("keys differing only in secretKeySeed are equal",
            base.equals(keyHolding(params, 99, 2)));
    }

    private static PrivateKey keyHolding(XMSSParameters params, int secretKeySeed, int secretKeyPRF)
    {
        return new BCXMSSPrivateKey(NISTObjectIdentifiers.id_sha256,
            new XMSSPrivateKeyParameters.Builder(params)
                .withSecretKeySeed(XMSSTestUtils.filled(secretKeySeed)).withSecretKeyPRF(XMSSTestUtils.filled(secretKeyPRF))
                .withPublicSeed(XMSSTestUtils.filled(3)).withRoot(XMSSTestUtils.filled(4)).build());
    }


    public void testKeyExtraction()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

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

    /**
     * A verification init does not strand the advanced key inside the signature object. The signer
     * this wraps keeps the private key across an init for verification on purpose - "sign then
     * verify then collect the advanced state is a legitimate sequence" is XMSSSigner.init's own
     * comment on why it clears the public key there and not the private one - and
     * getUpdatedPrivateKey() is how a caller of the JCA API collects it. isSigningCapable() still
     * answers false in between, because this object is initialised for verification.
     */
    public void testKeyCanBeCollectedAfterAVerificationInit()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        StateAwareSignature sig = (StateAwareSignature)Signature.getInstance("SHA256withXMSS", "BCPQC");

        // taken before the signature, because the object kp.getPrivate() hands back wraps the
        // traversal state the signature advances in place - so it reports the advanced position
        // afterwards, and the assertEquals below is two views of one mutated key rather than a
        // statement about which key came back. These bytes are the only record of where it started.
        byte[] before = kp.getPrivate().getEncoded();

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
        assertFalse("initialised for verification and reporting itself able to sign",
            sig.isSigningCapable());

        PrivateKey collected = sig.getUpdatedPrivateKey();

        assertNotNull("the advanced key was not handed back after a verification init", collected);
        assertFalse("the key handed back sits where it did before the signature",
            Arrays.areEqual(before, collected.getEncoded()));
        assertEquals("the key handed back is not the one the signature advanced",
            kp.getPrivate(), collected);
    }

    /**
     * Collecting the key without having signed leaves this object able to sign, and saying so.
     * The signer hands back the key advanced past the leaf it is holding and keeps a one-usage
     * shard of that leaf, so sign() still works afterwards - what isSigningCapable() used to
     * answer from was the SPI's own treeDigest field, which getUpdatedPrivateKey() cleared on
     * every call whether a signature had been made or not, so the object reported itself unable
     * to do the thing it then did.
     */
    public void testCollectingWithoutSigningLeavesTheObjectAbleToSign()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        StateAwareSignature sig = (StateAwareSignature)Signature.getInstance("SHA256withXMSS", "BCPQC");

        sig.initSign(kp.getPrivate());

        PrivateKey collected = sig.getUpdatedPrivateKey();

        assertNotNull(collected);
        assertTrue("the object kept a usable key and reported that it had not",
            sig.isSigningCapable());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        assertFalse("the shard is spent and the object says it is not", sig.isSigningCapable());

        Signature verifier = Signature.getInstance("SHA256withXMSS", "BCPQC");

        verifier.initVerify(kp.getPublic());
        verifier.update(msg, 0, msg.length);

        assertTrue("the retained shard did not produce a verifiable signature", verifier.verify(s));
    }

    /**
     * An initialize() that cannot be satisfied leaves the generator where it was. The tree digest
     * was written into the field before the parameter set was built, so a height the parameter set
     * refuses left this generator naming a digest the engine it hands keys to knows nothing about,
     * and the next generateKeyPair() - which the earlier, successful initialize had made legal -
     * produced a key labelled with it. The refusal itself is reported as the
     * InvalidAlgorithmParameterException the method declares rather than as the unchecked
     * IllegalArgumentException the parameter set raises.
     */
    public void testAFailedInitialiseLeavesTheGeneratorAsItWas()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        String treeDigest = ((XMSSKey)kpg.generateKeyPair().getPublic()).getTreeDigest();

        try
        {
            kpg.initialize(new XMSSParameterSpec(1, XMSSParameterSpec.SHAKE256), new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("height must be >= 2", e.getMessage());
        }

        assertEquals("the refused initialize left its tree digest behind",
            treeDigest, ((XMSSKey)kpg.generateKeyPair().getPublic()).getTreeDigest());
    }

    public void testKeyRebuild()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(3, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSS", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        PrivateKey pKey1 = ((XMSSPrivateKey)kp.getPrivate()).extractKeyShard(7);

        sig.initSign(pKey1);

        for (int i = 0; i != 7; i++)
        {
            sig.update(msg, 0, msg.length);

            sig.sign();
        }

        PrivateKey pKey = kp.getPrivate();

        PrivateKeyInfo pKeyInfo = PrivateKeyInfo.getInstance(pKey.getEncoded());

        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", "BCPQC");

        ASN1Sequence seq = ASN1Sequence.getInstance(pKeyInfo.parsePrivateKey());

        // create a new PrivateKeyInfo containing a key with no BDS state.
        pKeyInfo = new PrivateKeyInfo(pKeyInfo.getPrivateKeyAlgorithm(),
            new DERSequence(new ASN1Encodable[]{seq.getObjectAt(0), seq.getObjectAt(1)}));

        XMSSKey privKey = (XMSSKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pKeyInfo.getEncoded()));

        sig.initSign(pKey);

        sig.update(msg, 0, msg.length);

        byte[] sig1 = sig.sign();

        sig.initSign((PrivateKey)privKey);

        sig.update(msg, 0, msg.length);

        byte[] sig2 = sig.sign();

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
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHAKE128_512ph, BCObjectIdentifiers.xmss_SHAKE128, "SHAKE128", new XMSSTestUtils.DoubleDigest(new SHAKEDigest(128)));
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHA512ph, BCObjectIdentifiers.xmss_SHA512, "SHA512", new SHA512Digest());
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHAKE256ph, BCObjectIdentifiers.xmss_SHAKE256, "SHAKE256", new SHAKEDigest(256));
        testPrehashAndWithoutPrehash(BCObjectIdentifiers.xmss_SHAKE256_1024ph, BCObjectIdentifiers.xmss_SHAKE256, "SHAKE256", new XMSSTestUtils.DoubleDigest(new SHAKEDigest(256)));
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

    public void testStrengthInitialisation()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        try
        {
            kpg.initialize(10, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidParameterException e)
        {
            // what KeyPairGenerator.initialize(int, SecureRandom) is specified to throw; it
            // extends IllegalArgumentException, so a caller catching that still sees this one
            assertEquals("use AlgorithmParameterSpec", e.getMessage());
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

        byte[] dig = new byte[digest.getDigestSize()];

        digest.doFinal(dig, 0);

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


    /**
     * A key loaded from a PKCS#8 that carried attributes keeps them across the two operations that
     * hand back a new key object for the same key: getUpdatedPrivateKey(), which is how
     * StateAwareSignature says to take the advanced key after signing, and extractKeyShard().
     * <p>
     * Both re-wrapped the advanced key parameters through the two-argument BCXMSSPrivateKey
     * constructor, which sets no attributes, so the attributes were dropped - silently, since
     * everything else about the key survives and the encoding is still well formed. Taking the key
     * back after every signature is the whole of how a stateful scheme is used, so this is the
     * path a key with attributes travels every time it signs.
     * </p>
     */
    public void testAttributesSurviveSigningAndSharding()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("XMSS", "BCPQC");

        PrivateKey withAttributes = kf.generatePrivate(
            new PKCS8EncodedKeySpec(XMSSTestUtils.withAttributes(kp.getPrivate().getEncoded())));

        assertEquals("the loaded key did not carry the attributes",
            XMSSTestUtils.ATTRIBUTES, XMSSTestUtils.attributesOf(withAttributes.getEncoded()));

        StateAwareSignature sig = (StateAwareSignature)Signature.getInstance("SHA256withXMSS", "BCPQC");

        sig.initSign(withAttributes);
        sig.update(msg, 0, msg.length);
        sig.sign();

        assertEquals("getUpdatedPrivateKey() dropped the attributes",
            XMSSTestUtils.ATTRIBUTES,
            XMSSTestUtils.attributesOf(sig.getUpdatedPrivateKey().getEncoded()));

        assertEquals("extractKeyShard() dropped the attributes", XMSSTestUtils.ATTRIBUTES,
            XMSSTestUtils.attributesOf(((XMSSPrivateKey)withAttributes).extractKeyShard(1).getEncoded()));

        // a generated key has no origin to take attributes from, and must still encode without any
        assertNull("a generated key invented attributes", XMSSTestUtils.attributesOf(kp.getPrivate().getEncoded()));
    }

    /**
     * Two threads comparing the same pair of keys in opposite orders both finish. equals() reads a
     * key's index and usages remaining under that key's own monitor - the monitor a signature holds
     * for the whole of its length - and it takes the two keys' monitors one after the other rather
     * than one inside the other, so an a.equals(b) and a b.equals(a) running at the same time can
     * never each be holding the one the other is waiting on. Nested, they deadlock here in a few
     * rounds, and the two threads are still alive when the joins time out.
     * <p>
     * The two keys are equal, so every round runs the whole of the method: both position reads and,
     * behind them, both traversal state encodings, each taking a monitor of its own.
     * </p>
     */
    public void testEqualsTakesTheTwoKeyMonitorsOneAtATime()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyFactory kf = KeyFactory.getInstance("XMSS", "BCPQC");
        byte[] encoding = kpg.generateKeyPair().getPrivate().getEncoded();

        PrivateKey one = kf.generatePrivate(new PKCS8EncodedKeySpec(encoding));
        PrivateKey two = kf.generatePrivate(new PKCS8EncodedKeySpec(encoding));

        assertEquals("the two keys are not equal to begin with", one, two);

        boolean[] agreed = new boolean[2];
        Thread forwards = XMSSTestUtils.comparing(one, two, agreed, 0);
        Thread backwards = XMSSTestUtils.comparing(two, one, agreed, 1);

        forwards.start();
        backwards.start();

        forwards.join(60000);
        backwards.join(60000);

        assertFalse("comparing the two keys in both orders at once did not finish",
            forwards.isAlive() || backwards.isAlive());
        assertTrue("equals() answered false for two keys that are equal", agreed[0] && agreed[1]);
    }
}
