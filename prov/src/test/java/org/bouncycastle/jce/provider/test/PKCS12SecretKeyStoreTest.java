package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.pkcs.SecretBag;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Phase 1 of github #1807: SecretKey storage in PKCS#12, encoded per
 * RFC 7292 sec. 4.2.5 secretBag. Algorithms must have a registered OID.
 */
public class PKCS12SecretKeyStoreTest
    extends SimpleTest
{
    private static final char[] PASSWD = "secret".toCharArray();

    public String getName()
    {
        return "PKCS12SecretKey";
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        roundTripAes256();
        roundTripHmacSha256();
        roundTripDesEde();
        roundTripSeed();
        roundTripAria192();
        roundTripCamellia256();
        roundTripWithKnownOidAsAlgorithmName();
        roundTripWithUnknownOidAsAlgorithmName();
        mixedEntriesRoundTrip();
        unsupportedAlgorithmRejected();
        deleteSecretKeyEntry();
        roundTripPbmac1();
        sunStyleSecretBag_propertyOff();
        sunStyleSecretBag_propertyOn();
    }

    /**
     * Algorithm name supplied as an ASN.1 OID string for an OID we DO have a
     * canonical name for: round-trip succeeds and the load-side algorithm
     * resolves back to the canonical JCA name.
     */
    private void roundTripWithKnownOidAsAlgorithmName()
        throws Exception
    {
        // 1.2.840.113549.2.9 == id-hmacWithSHA256
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x71 ^ i);
        }
        SecretKey hmac = new SecretKeySpec(keyBytes, "1.2.840.113549.2.9");

        KeyStore writer = KeyStore.getInstance("PKCS12", "BC");
        writer.load(null, null);
        writer.setKeyEntry("oid-hmac", hmac, PASSWD, null);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writer.store(buf, PASSWD);

        KeyStore reader = KeyStore.getInstance("PKCS12", "BC");
        reader.load(new ByteArrayInputStream(buf.toByteArray()), PASSWD);

        Key recovered = reader.getKey("oid-hmac", PASSWD);
        if (!(recovered instanceof SecretKey))
        {
            fail("oid-hmac: recovered key not a SecretKey, was " + recovered.getClass());
        }
        if (!"HmacSHA256".equalsIgnoreCase(recovered.getAlgorithm()))
        {
            fail("oid-hmac: expected canonical name HmacSHA256, got " + recovered.getAlgorithm());
        }
        if (!Arrays.areEqual(keyBytes, recovered.getEncoded()))
        {
            fail("oid-hmac: encoded key bytes differ after round-trip");
        }
    }

    /**
     * Algorithm name supplied as an ASN.1 OID string the BC table doesn't
     * know about. The OID is stored verbatim as the secretTypeId; on load
     * the SecretKey's algorithm name comes back as the OID's string form
     * (SecretKeySpec accepts arbitrary names).
     */
    private void roundTripWithUnknownOidAsAlgorithmName()
        throws Exception
    {
        String customOid = "1.3.5.7.9.11";
        byte[] keyBytes = new byte[16];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x84 + i);
        }
        SecretKey custom = new SecretKeySpec(keyBytes, customOid);

        KeyStore writer = KeyStore.getInstance("PKCS12", "BC");
        writer.load(null, null);
        writer.setKeyEntry("custom-oid", custom, PASSWD, null);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writer.store(buf, PASSWD);

        KeyStore reader = KeyStore.getInstance("PKCS12", "BC");
        reader.load(new ByteArrayInputStream(buf.toByteArray()), PASSWD);

        Key recovered = reader.getKey("custom-oid", PASSWD);
        if (!(recovered instanceof SecretKey))
        {
            fail("custom-oid: recovered key not a SecretKey, was " + recovered.getClass());
        }
        if (!customOid.equals(recovered.getAlgorithm()))
        {
            fail("custom-oid: expected algorithm " + customOid + ", got " + recovered.getAlgorithm());
        }
        if (!Arrays.areEqual(keyBytes, recovered.getEncoded()))
        {
            fail("custom-oid: encoded key bytes differ after round-trip");
        }
    }

    private void roundTripSeed()
        throws Exception
    {
        byte[] keyBytes = new byte[16];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x70 ^ i);
        }
        roundTripSingleSecretKey("seed", new SecretKeySpec(keyBytes, "SEED"));
    }

    private void roundTripAria192()
        throws Exception
    {
        byte[] keyBytes = new byte[24];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x33 ^ i);
        }
        roundTripSingleSecretKey("aria-192", new SecretKeySpec(keyBytes, "ARIA"));
    }

    private void roundTripCamellia256()
        throws Exception
    {
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x05 + i);
        }
        roundTripSingleSecretKey("camellia-256", new SecretKeySpec(keyBytes, "Camellia"));
    }

    /**
     * Build a SunJCE-style PKCS#12 byte stream containing an AES-128 secret
     * key encoded as a SafeBag(secretBag, SecretBag(secretTypeId =
     * pkcs8ShroudedKeyBag, secretValue = OCTET STRING wrapping an
     * EncryptedPrivateKeyInfo whose decrypted PKCS#8 carries the raw key
     * bytes and an AES algorithm OID)).
     */
    private static byte[] buildSunStyleSecretKeyPfx(SecretKey secretKey, char[] password)
        throws Exception
    {
        // Build the PKCS#8 PrivateKeyInfo SunJCE-style: privateKeyAlgorithm
        // is the secret-key algorithm OID, privateKey OCTET STRING contains
        // the raw key bytes.
        AlgorithmIdentifier secretAlgId =
            new AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes128_CBC);
        // PrivateKeyInfo's (AlgorithmIdentifier, byte[]) constructor wraps the
        // raw bytes in the privateKey OCTET STRING — what SunJCE produces for
        // a SecretKey entry.
        PrivateKeyInfo pki = new PrivateKeyInfo(secretAlgId, secretKey.getEncoded());

        // Encrypt the PKCS#8 with PKCS12 PBE/SHA1/3DES (a standard scheme).
        byte[] salt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        int iter = 2048;
        AlgorithmIdentifier encAlg = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
            new PKCS12PBEParams(salt, iter));

        Cipher cipher = Cipher.getInstance(
            PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId(), "BC");
        cipher.init(Cipher.ENCRYPT_MODE,
            new PKCS12Key(password, false),
            new PBEParameterSpec(salt, iter));
        byte[] encryptedPki = cipher.doFinal(pki.getEncoded(ASN1Encoding.DER));

        EncryptedPrivateKeyInfo encInfo = new EncryptedPrivateKeyInfo(encAlg, encryptedPki);

        SecretBag inner = new SecretBag(
            PKCSObjectIdentifiers.pkcs8ShroudedKeyBag,
            new DEROctetString(encInfo.getEncoded(ASN1Encoding.DER)));

        // friendlyName attribute so the load picks up the alias.
        DERSequence friendlyName = new DERSequence(
            new org.bouncycastle.asn1.ASN1Encodable[]{
                PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERSet(new DERBMPString("sun-aes"))
            });
        SafeBag safeBag = new SafeBag(
            PKCSObjectIdentifiers.secretBag,
            inner.toASN1Primitive(),
            new DERSet(friendlyName));

        // Wrap the SafeBag in an encrypted SafeContents block (matching
        // BC's load-side expectations).
        byte[] safeContents = new DERSequence(safeBag).getEncoded(ASN1Encoding.DER);
        Cipher contentCipher = Cipher.getInstance(
            PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId(), "BC");
        contentCipher.init(Cipher.ENCRYPT_MODE,
            new PKCS12Key(password, false),
            new PBEParameterSpec(salt, iter));
        byte[] encryptedContents = contentCipher.doFinal(safeContents);

        EncryptedData encData = new EncryptedData(PKCSObjectIdentifiers.data, encAlg,
            new DEROctetString(encryptedContents));
        ContentInfo encContentInfo = new ContentInfo(PKCSObjectIdentifiers.encryptedData,
            encData.toASN1Primitive());

        AuthenticatedSafe authSafe = AuthenticatedSafe.getInstance(
            new DERSequence(encContentInfo).toASN1Primitive());
        ContentInfo mainInfo = new ContentInfo(PKCSObjectIdentifiers.data,
            new DEROctetString(authSafe.getEncoded(ASN1Encoding.DER)));

        // MAC over the AuthenticatedSafe content octets (matches
        // PKCS12KeyStoreSpi.calculatePbeMac for SHA-1 PBE).
        byte[] macSalt = new byte[]{(byte)0xa, (byte)0xb, (byte)0xc, (byte)0xd, (byte)0xe, (byte)0xf, 0x10, 0x11};
        int macIter = 2048;
        byte[] mac = computePkcs12Mac(
            authSafe.getEncoded(ASN1Encoding.DER), password, macSalt, macIter);
        DigestInfo dInfo = new DigestInfo(
            new AlgorithmIdentifier(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.14.3.2.26"), DERNull.INSTANCE), mac);
        MacData macData = new MacData(dInfo, macSalt, macIter);

        Pfx pfx = new Pfx(mainInfo, macData);
        return pfx.getEncoded(ASN1Encoding.DER);
    }

    private static byte[] computePkcs12Mac(byte[] data, char[] password, byte[] salt, int iter)
        throws Exception
    {
        SHA1Digest digest = new SHA1Digest();
        PKCS12ParametersGenerator pgen = new PKCS12ParametersGenerator(digest);
        pgen.init(PKCS12ParametersGenerator.PKCS12PasswordToBytes(password), salt, iter);
        KeyParameter keyParam = (KeyParameter)pgen.generateDerivedMacParameters(digest.getDigestSize() * 8);

        HMac hmac = new HMac(new SHA1Digest());
        hmac.init(keyParam);
        hmac.update(data, 0, data.length);
        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }

    private void sunStyleSecretBag_propertyOff()
        throws Exception
    {
        SecretKey aes = new SecretKeySpec(new byte[16], "AES");
        byte[] pfxBytes = buildSunStyleSecretKeyPfx(aes, PASSWD);

        // With the property unset, SunJCE-style secretBag entries should be
        // rejected as an unrecognised algorithm (the secretTypeId is
        // pkcs8ShroudedKeyBag, which isn't in the standard secretBag table).
        Properties.removeThreadOverride(Properties.PKCS12_ALLOW_SUN_SECRET_KEYS);
        KeyStore reader = KeyStore.getInstance("PKCS12", "BC");
        try
        {
            reader.load(new ByteArrayInputStream(pfxBytes), PASSWD);
            fail("propertyOff: SunJCE-style secretBag accepted without opt-in");
        }
        catch (java.io.IOException e)
        {
            if (e.getMessage() == null || e.getMessage().indexOf("unrecognised PKCS12 secretBag algorithm") < 0)
            {
                fail("propertyOff: unexpected message: " + e.getMessage());
            }
        }
    }

    private void sunStyleSecretBag_propertyOn()
        throws Exception
    {
        byte[] keyBytes = new byte[16];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x42 + i);
        }
        SecretKey aes = new SecretKeySpec(keyBytes, "AES");
        byte[] pfxBytes = buildSunStyleSecretKeyPfx(aes, PASSWD);

        Properties.setThreadOverride(Properties.PKCS12_ALLOW_SUN_SECRET_KEYS, true);
        try
        {
            KeyStore reader = KeyStore.getInstance("PKCS12", "BC");
            reader.load(new ByteArrayInputStream(pfxBytes), PASSWD);

            Key recovered = reader.getKey("sun-aes", PASSWD);
            if (!(recovered instanceof SecretKey))
            {
                fail("propertyOn: recovered key not a SecretKey, was "
                    + (recovered == null ? "null" : recovered.getClass().toString()));
            }
            if (!"AES".equalsIgnoreCase(recovered.getAlgorithm()))
            {
                fail("propertyOn: algorithm mismatch — got " + recovered.getAlgorithm());
            }
            if (!Arrays.areEqual(keyBytes, recovered.getEncoded()))
            {
                fail("propertyOn: encoded key bytes differ after load");
            }
        }
        finally
        {
            Properties.removeThreadOverride(Properties.PKCS12_ALLOW_SUN_SECRET_KEYS);
        }
    }

    private void roundTripPbmac1()
        throws Exception
    {
        byte[] keyBytes = new byte[24];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x55 ^ i);
        }
        SecretKey aes192 = new SecretKeySpec(keyBytes, "AES");

        KeyStore writer = KeyStore.getInstance("PKCS12-PBMAC1", "BC");
        writer.load(null, null);
        writer.setKeyEntry("aes-pbmac1", aes192, PASSWD, null);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writer.store(buf, PASSWD);

        KeyStore reader = KeyStore.getInstance("PKCS12-PBMAC1", "BC");
        reader.load(new ByteArrayInputStream(buf.toByteArray()), PASSWD);

        Key recovered = reader.getKey("aes-pbmac1", PASSWD);
        if (!(recovered instanceof SecretKey))
        {
            fail("PBMAC1: recovered key not a SecretKey, was " + recovered.getClass());
        }
        if (!Arrays.areEqual(keyBytes, recovered.getEncoded()))
        {
            fail("PBMAC1: encoded key bytes differ after round-trip");
        }
        if (reader.entryInstanceOf("aes-pbmac1", KeyStore.SecretKeyEntry.class) == false)
        {
            fail("PBMAC1: loaded entry not classified as SecretKeyEntry");
        }
    }

    private void roundTripAes256()
        throws Exception
    {
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(i + 1);
        }
        roundTripSingleSecretKey("aes-256", new SecretKeySpec(keyBytes, "AES"));
    }

    private void roundTripHmacSha256()
        throws Exception
    {
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0xa0 ^ i);
        }
        roundTripSingleSecretKey("hmac", new SecretKeySpec(keyBytes, "HmacSHA256"));
    }

    private void roundTripDesEde()
        throws Exception
    {
        byte[] keyBytes = new byte[24];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x10 + i);
        }
        roundTripSingleSecretKey("3des", new SecretKeySpec(keyBytes, "DESede"));
    }

    private void roundTripSingleSecretKey(String alias, SecretKey key)
        throws Exception
    {
        KeyStore writer = KeyStore.getInstance("PKCS12", "BC");
        writer.load(null, null);
        writer.setKeyEntry(alias, key, PASSWD, null);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writer.store(buf, PASSWD);

        KeyStore reader = KeyStore.getInstance("PKCS12", "BC");
        reader.load(new ByteArrayInputStream(buf.toByteArray()), PASSWD);

        if (!reader.containsAlias(alias))
        {
            fail(alias + ": alias missing after load");
        }
        if (!reader.isKeyEntry(alias))
        {
            fail(alias + ": loaded entry is not a key entry");
        }
        if (reader.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class) == false)
        {
            fail(alias + ": loaded entry not classified as SecretKeyEntry");
        }
        if (reader.getCertificate(alias) != null)
        {
            fail(alias + ": SecretKey entry returned a certificate");
        }
        if (reader.getCertificateChain(alias) != null)
        {
            fail(alias + ": SecretKey entry returned a chain");
        }

        Key recovered = reader.getKey(alias, PASSWD);
        if (!(recovered instanceof SecretKey))
        {
            fail(alias + ": recovered key not a SecretKey, was " + recovered.getClass());
        }
        SecretKey rs = (SecretKey)recovered;
        if (!key.getAlgorithm().equalsIgnoreCase(rs.getAlgorithm()))
        {
            fail(alias + ": algorithm mismatch — wrote " + key.getAlgorithm()
                + ", read " + rs.getAlgorithm());
        }
        if (!Arrays.areEqual(key.getEncoded(), rs.getEncoded()))
        {
            fail(alias + ": encoded key bytes differ after round-trip");
        }
    }

    private void mixedEntriesRoundTrip()
        throws Exception
    {
        // Build an issuer + leaf chain, an unrelated trusted cert, and a SecretKey.
        java.security.KeyPair caKp = TestUtils.generateRSAKeyPair();
        java.security.KeyPair eeKp = TestUtils.generateRSAKeyPair();
        X509Certificate caCert = TestUtils.generateRootCert(caKp);
        X509Certificate eeCert = TestUtils.generateEndEntityCert(eeKp.getPublic(), caKp.getPrivate(), caCert);
        Certificate[] chain = new Certificate[]{eeCert, caCert};

        SecretKey aes = new SecretKeySpec(new byte[16], "AES");

        KeyStore writer = KeyStore.getInstance("PKCS12", "BC");
        writer.load(null, null);
        writer.setKeyEntry("ee", eeKp.getPrivate(), PASSWD, chain);
        writer.setCertificateEntry("ca", caCert);
        writer.setKeyEntry("aes", aes, PASSWD, null);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writer.store(buf, PASSWD);

        KeyStore reader = KeyStore.getInstance("PKCS12", "BC");
        reader.load(new ByteArrayInputStream(buf.toByteArray()), PASSWD);

        Set aliases = new HashSet();
        Enumeration en = reader.aliases();
        while (en.hasMoreElements())
        {
            aliases.add(en.nextElement());
        }
        if (!aliases.contains("ee") || !aliases.contains("ca") || !aliases.contains("aes"))
        {
            fail("mixed: aliases missing after load: " + aliases);
        }

        // Private-key entry survives with chain.
        if (!(reader.getKey("ee", PASSWD) instanceof java.security.PrivateKey))
        {
            fail("mixed: ee not a PrivateKey after load");
        }
        Certificate[] readChain = reader.getCertificateChain("ee");
        if (readChain == null || readChain.length != 2)
        {
            fail("mixed: ee chain length wrong: "
                + (readChain == null ? "null" : Integer.toString(readChain.length)));
        }

        // Cert-only entry survives.
        if (reader.isKeyEntry("ca") || !reader.isCertificateEntry("ca"))
        {
            fail("mixed: ca lost cert-entry classification");
        }

        // SecretKey entry survives.
        Key recovered = reader.getKey("aes", PASSWD);
        if (!(recovered instanceof SecretKey)
            || !Arrays.areEqual(aes.getEncoded(), recovered.getEncoded()))
        {
            fail("mixed: aes secret key didn't round-trip");
        }
        if (reader.entryInstanceOf("aes", KeyStore.SecretKeyEntry.class) == false)
        {
            fail("mixed: aes not classified as SecretKeyEntry");
        }
    }

    private void unsupportedAlgorithmRejected()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);

        SecretKey weird = new SecretKeySpec(new byte[16], "Made-Up-Cipher");
        try
        {
            ks.setKeyEntry("weird", weird, PASSWD, null);
            fail("expected setKeyEntry to reject Made-Up-Cipher SecretKey");
        }
        catch (KeyStoreException e)
        {
            if (e.getMessage() == null
                || e.getMessage().indexOf("registered OID") < 0)
            {
                fail("unexpected message: " + e.getMessage());
            }
        }
    }

    private void deleteSecretKeyEntry()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry("aes", new SecretKeySpec(new byte[32], "AES"), PASSWD, null);

        if (!ks.containsAlias("aes"))
        {
            fail("aes alias missing before delete");
        }
        ks.deleteEntry("aes");
        if (ks.containsAlias("aes"))
        {
            fail("aes alias still present after delete");
        }
    }

    public static void main(String[] args)
    {
        runTest(new PKCS12SecretKeyStoreTest());
    }
}
