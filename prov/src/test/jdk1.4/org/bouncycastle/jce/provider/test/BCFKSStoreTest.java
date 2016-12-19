package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Exercise the  BCFKS KeyStore,
 */
public class BCFKSStoreTest
    extends SimpleTest
{
    private static byte[] trustedCertData = Base64.decode(
        "MIIB/DCCAaagAwIBAgIBATANBgkqhkiG9w0BAQQFADCBhjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIE" +
            "JvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExJjAkBgkqhkiG9w0BCQEWF2lzc3VlckBi" +
            "b3VuY3ljYXN0bGUub3JnMB4XDTE0MDIyODExMjcxMVoXDTE0MDQyOTExMjcxMVowgYcxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaG" +
            "UgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMScwJQYJKoZI" +
            "hvcNAQkBFhhzdWJqZWN0QGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5" +
            "hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkqhkiG9w0BAQQFAANBAJ/ZhfF21NykhbEY" +
            "RQrAo/yRr9XfpmBTVUSlLJXYoNVVRT5u9SGQqmPNfHElrTvNMZQPC0ridDZtBWb6S2tg9/E=");

    static char[] testPassword = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    static char[] invalidTestPassword = {'Y', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};


    public void shouldCreateEmptyBCFKSNoPassword()
        throws Exception
    {
        checkEmptyStore(null);
    }

    public void shouldCreateEmptyBCFKSPassword()
        throws Exception
    {
        checkEmptyStore(testPassword);
    }

    private void checkEmptyStore(char[] passwd)
        throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException
    {
        KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

        store1.load(null, null);

        isTrue("", 0 == store1.size());
        isTrue("", !store1.aliases().hasMoreElements());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store1.store(bOut, passwd);

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        isTrue("", 0 == store2.size());
        isTrue("", !store2.aliases().hasMoreElements());

        checkInvalidLoad(store2, passwd, bOut.toByteArray());
    }

    private void checkInvalidLoad(KeyStore store, char[] passwd, byte[] data)
        throws NoSuchAlgorithmException, CertificateException, KeyStoreException
    {
        checkInvalidLoadForPassword(store, invalidTestPassword, data);

        if (passwd != null)
        {
            checkInvalidLoadForPassword(store, null, data);
        }
    }

    private void checkInvalidLoadForPassword(KeyStore store, char[] password, byte[] data)
        throws NoSuchAlgorithmException, CertificateException, KeyStoreException
    {
        try
        {
            store.load(new ByteArrayInputStream(data), password);
        }
        catch (IOException e)
        {
            isTrue("wrong message", "BCFKS KeyStore corrupted: MAC calculation failed.".equals(e.getMessage()));
        }

        isTrue("", 0 == store.size());
        isTrue("", !store.aliases().hasMoreElements());
    }

    public void shouldStoreOneCertificate()
        throws Exception
    {
        X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(trustedCertData));

        checkOneCertificate(cert, null);
        checkOneCertificate(cert, testPassword);
    }

    private void checkOneCertificate(X509Certificate cert, char[] passwd)
        throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException
    {
        KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

        store1.load(null, null);

        store1.setCertificateEntry("cert", cert);

        isTrue("", 1 == store1.size());
        Enumeration<String> en1 = store1.aliases();

        isTrue("", "cert".equals(en1.nextElement()));
        isTrue("", !en1.hasMoreElements());

        certStorageCheck(store1, "cert", cert);

        Date entryDate = store1.getCreationDate("cert");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store1.store(bOut, passwd);

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        isTrue("", entryDate.equals(store2.getCreationDate("cert")));
        isTrue("", 1 == store2.size());
        Enumeration<String> en2 = store2.aliases();

        isTrue("", "cert".equals(en2.nextElement()));
        isTrue("", !en2.hasMoreElements());

        certStorageCheck(store2, "cert", cert);

        // check invalid load with content

        checkInvalidLoad(store2, passwd, bOut.toByteArray());

        // check deletion on purpose

        store1.deleteEntry("cert");

        isTrue("", 0 == store1.size());
        isTrue("", !store1.aliases().hasMoreElements());

        bOut = new ByteArrayOutputStream();

        store1.store(bOut, passwd);

        store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        isTrue("", 0 == store2.size());
        isTrue("", !store2.aliases().hasMoreElements());
    }

    public void shouldStoreOnePrivateKey()
        throws Exception
    {
        PrivateKey privKey = getPrivateKey();

        X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(trustedCertData));

        checkOnePrivateKeyFips(privKey, new X509Certificate[] { cert }, null);
        checkOnePrivateKeyFips(privKey, new X509Certificate[] { cert }, testPassword);
        checkOnePrivateKeyDef(privKey, new X509Certificate[] { cert }, null);
        checkOnePrivateKeyDef(privKey, new X509Certificate[] { cert }, testPassword);
    }

    public void shouldStoreOnePrivateKeyWithChain()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(512);

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withRSA", kp2);
        X509Certificate interCert = TestUtils.createCert(
            TestUtils.getCertSubject(finalCert),
            kp2.getPrivate(),
            "CN=EE",
            "SHA1withRSA",
            null,
            kp1.getPublic());

        checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
        checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);

        checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
        checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);
    }

    public void shouldStoreOneECKeyWithChain()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(256);

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withECDSA", kp2);
        X509Certificate interCert = TestUtils.createCert(
            TestUtils.getCertSubject(finalCert),
            kp2.getPrivate(),
            "CN=EE",
            "SHA1withECDSA",
            null,
            kp1.getPublic());

        checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
        checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);

        checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
        checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);
    }

    public void shouldRejectInconsistentKeys()
        throws Exception
    {
        PrivateKey privKey = getPrivateKey();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));

        KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

        store1.load(null, null);

        try
        {
            store1.setKeyEntry("privkey", privKey, "hello".toCharArray(), new X509Certificate[]{interCert});
            fail("no exception");
        }
        catch (KeyStoreException e)
        {
            isTrue("", "RSA keys do not have the same modulus".equals(e.getCause().getMessage()));
        }
    }

    private void checkOnePrivateKeyFips(PrivateKey key, X509Certificate[] certs, char[] passwd)
        throws Exception
    {
        KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

        store1.load(null, null);

        checkOnePrivateKey(key, store1, certs, passwd);
    }

    private void checkOnePrivateKeyDef(PrivateKey key, X509Certificate[] certs, char[] passwd)
        throws Exception
    {
        KeyStore store1 = KeyStore.getInstance("BCFKS-DEF", "BC");

        store1.load(null, null);

        checkOnePrivateKey(key, store1, certs, passwd);
    }

    private void checkOnePrivateKey(PrivateKey key, KeyStore store1, X509Certificate[] certs, char[] passwd)
        throws Exception
    {
        store1.setKeyEntry("privkey", key, passwd, certs);

        isTrue("", 1 == store1.size());
        Enumeration<String> en1 = store1.aliases();

        isTrue("", "privkey".equals(en1.nextElement()));
        isTrue("", !en1.hasMoreElements());

        privateKeyStorageCheck(store1, "privkey", key, certs[0], passwd);

        Date entryDate = store1.getCreationDate("privkey");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store1.store(bOut, passwd);

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        isTrue("", store2.getCertificateChain("privkey").length == certs.length);
        Certificate[] sChain = store2.getCertificateChain("privkey");
        for (int i = 0; i != sChain.length; i++)
        {
            isTrue("", certs[i].equals(sChain[i]));
        }
        isTrue("", entryDate.equals(store2.getCreationDate("privkey")));
        isTrue("", 1 == store2.size());
        Enumeration<String> en2 = store2.aliases();

        isTrue("", "privkey".equals(en2.nextElement()));
        isTrue("", !en2.hasMoreElements());

        privateKeyStorageCheck(store2, "privkey", key, certs[0], passwd);

        // check invalid load with content

        checkInvalidLoad(store2, passwd, bOut.toByteArray());

        // check deletion on purpose

        store1.deleteEntry("privkey");

        isTrue("", 0 == store1.size());
        isTrue("", !store1.aliases().hasMoreElements());

        bOut = new ByteArrayOutputStream();

        store1.store(bOut, passwd);

        store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        isTrue("", 0 == store2.size());
        isTrue("", !store2.aliases().hasMoreElements());
    }

    public void shouldStoreMultipleKeys()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(512);

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withRSA", kp2);
        X509Certificate interCert = TestUtils.createCert(
            TestUtils.getCertSubject(finalCert),
            kp2.getPrivate(),
            "CN=EE",
            "SHA1withRSA",
            null,
            kp1.getPublic());

        PrivateKey privKey = kp1.getPrivate();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(trustedCertData));

        KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

        store1.load(null, null);

        store1.setKeyEntry("privkey", privKey, testPassword, new X509Certificate[]{interCert, finalCert});
        store1.setCertificateEntry("trusted", cert);
        SecretKeySpec aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "AES");
        store1.setKeyEntry("secret1", aesKey, "secretPwd1".toCharArray(), null);
        SecretKeySpec edeKey = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "DESede");
        store1.setKeyEntry("secret2", edeKey, "secretPwd2".toCharArray(), null);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store1.store(bOut, testPassword);

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), testPassword);

        isTrue("", 4 ==store2.size());

        Key storeDesEde = store2.getKey("secret2", "secretPwd2".toCharArray());

        isTrue("", edeKey.getAlgorithm().equals(storeDesEde.getAlgorithm()));

        isTrue("", Arrays.areEqual(edeKey.getEncoded(), storeDesEde.getEncoded()));

        Key storeAes = store2.getKey("secret1", "secretPwd1".toCharArray());
        isTrue("", Arrays.areEqual(aesKey.getEncoded(), storeAes.getEncoded()));
        isTrue("", aesKey.getAlgorithm().equals(storeAes.getAlgorithm()));

        Key storePrivKey = store2.getKey("privkey", testPassword);
        isTrue("", privKey.equals(storePrivKey));
        isTrue("", 2 == store2.getCertificateChain("privkey").length);

        Certificate storeCert = store2.getCertificate("trusted");
        isTrue("", cert.equals(storeCert));

        isTrue("", null ==store2.getCertificate("unknown"));

        isTrue("", null ==store2.getCertificateChain("unknown"));

        isTrue("", !store2.isCertificateEntry("unknown"));

        isTrue("", !store2.isKeyEntry("unknown"));

        isTrue("", !store2.containsAlias("unknown"));
    }

    public void shouldStoreSecretKeys()
        throws Exception
    {
        KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

        store1.load(null, null);

        SecretKeySpec aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "AES");
        SecretKeySpec edeKey1 = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "DESede");
        SecretKeySpec edeKey2 = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "TripleDES");
        SecretKeySpec edeKey3 = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "TDEA");
        SecretKeySpec hmacKey1 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff"), "HmacSHA1");
        SecretKeySpec hmacKey224 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff"), "HmacSHA224");
        SecretKeySpec hmacKey256 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff01ff"), "HmacSHA256");
        SecretKeySpec hmacKey384 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff0102ff"), "HmacSHA384");
        SecretKeySpec hmacKey512 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff010203ff"), "HmacSHA512");

        store1.setKeyEntry("secret1", aesKey, "secretPwd1".toCharArray(), null);
        store1.setKeyEntry("secret2", edeKey1, "secretPwd2".toCharArray(), null);
        store1.setKeyEntry("secret3", edeKey2, "secretPwd3".toCharArray(), null);
        store1.setKeyEntry("secret4", edeKey3, "secretPwd4".toCharArray(), null);
        store1.setKeyEntry("secret5", hmacKey1, "secretPwd5".toCharArray(), null);
        store1.setKeyEntry("secret6", hmacKey224, "secretPwd6".toCharArray(), null);
        store1.setKeyEntry("secret7", hmacKey256, "secretPwd7".toCharArray(), null);
        store1.setKeyEntry("secret8", hmacKey384, "secretPwd8".toCharArray(), null);
        store1.setKeyEntry("secret9", hmacKey512, "secretPwd9".toCharArray(), null);

        checkSecretKey(store1, "secret1", "secretPwd1".toCharArray(), aesKey);
        checkSecretKey(store1, "secret2", "secretPwd2".toCharArray(), edeKey1); // TRIPLEDES and TDEA will convert to DESEDE
        checkSecretKey(store1, "secret3", "secretPwd3".toCharArray(), edeKey1);
        checkSecretKey(store1, "secret4", "secretPwd4".toCharArray(), edeKey1);
        checkSecretKey(store1, "secret5", "secretPwd5".toCharArray(), hmacKey1);
        checkSecretKey(store1, "secret6", "secretPwd6".toCharArray(), hmacKey224);
        checkSecretKey(store1, "secret7", "secretPwd7".toCharArray(), hmacKey256);
        checkSecretKey(store1, "secret8", "secretPwd8".toCharArray(), hmacKey384);
        checkSecretKey(store1, "secret9", "secretPwd9".toCharArray(), hmacKey512);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store1.store(bOut, "secretkeytest".toCharArray());

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), "secretkeytest".toCharArray());

        checkSecretKey(store2, "secret1", "secretPwd1".toCharArray(), aesKey);
        checkSecretKey(store2, "secret2", "secretPwd2".toCharArray(), edeKey1); // TRIPLEDES and TDEA will convert to DESEDE
        checkSecretKey(store2, "secret3", "secretPwd3".toCharArray(), edeKey1);
        checkSecretKey(store2, "secret4", "secretPwd4".toCharArray(), edeKey1);
        checkSecretKey(store2, "secret5", "secretPwd5".toCharArray(), hmacKey1);
        checkSecretKey(store2, "secret6", "secretPwd6".toCharArray(), hmacKey224);
        checkSecretKey(store2, "secret7", "secretPwd7".toCharArray(), hmacKey256);
        checkSecretKey(store2, "secret8", "secretPwd8".toCharArray(), hmacKey384);
        checkSecretKey(store2, "secret9", "secretPwd9".toCharArray(), hmacKey512);

        isTrue("", null ==store2.getKey("secret10", new char[0]));
    }

    private void checkSecretKey(KeyStore store, String alias, char[] passwd, SecretKey key)
        throws Exception
    {
        SecretKey sKey = (SecretKey)store.getKey(alias, passwd);

        isTrue("", Arrays.areEqual(key.getEncoded(), sKey.getEncoded()));
        isTrue("", key.getAlgorithm().equals(sKey.getAlgorithm()));

        if (!store.isKeyEntry(alias))
        {
            fail("key not identified as key entry");
        }
    }

    private PrivateKey getPrivateKey()
    {
        PrivateKey privKey = null;

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));


        try
        {
            KeyFactory fact = KeyFactory.getInstance("RSA", "BC");

            privKey = fact.generatePrivate(privKeySpec);
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
        }

        return privKey;
    }

    public void shouldStoreOneSecretKey()
        throws Exception
    {
        checkOneSecretKey(new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES"), null);
        checkOneSecretKey(new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES"), testPassword);
    }

    private void checkOneSecretKey(SecretKey key, char[] passwd)
        throws Exception
    {
        KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

        store1.load(null, null);

        store1.setKeyEntry("seckey", key, passwd, null);

        isTrue("", 1 == store1.size());
        Enumeration<String> en1 = store1.aliases();

        isTrue("", "seckey".equals(en1.nextElement()));
        isTrue("", !en1.hasMoreElements());

        secretKeyStorageCheck(store1, "seckey", key, passwd);

        Date entryDate = store1.getCreationDate("seckey");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store1.store(bOut, passwd);

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        isTrue("", entryDate.equals(store2.getCreationDate("seckey")));
        isTrue("", 1 == store2.size());
        Enumeration<String> en2 = store2.aliases();

        isTrue("", "seckey".equals(en2.nextElement()));
        isTrue("", !en2.hasMoreElements());

        secretKeyStorageCheck(store2, "seckey", key, passwd);

        // check invalid load with content

        checkInvalidLoad(store2, passwd, bOut.toByteArray());

        // check deletion on purpose

        store1.deleteEntry("seckey");

        isTrue("", 0 == store1.size());
        isTrue("", !store1.aliases().hasMoreElements());

        bOut = new ByteArrayOutputStream();

        store1.store(bOut, passwd);

        store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        isTrue("", 0 == store2.size());
        isTrue("", !store2.aliases().hasMoreElements());
    }

    private void privateKeyStorageCheck(KeyStore store, String keyName, PrivateKey key, Certificate cert, char[] password)
        throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
    {
        if (!store.containsAlias(keyName))
        {
            fail("couldn't find alias privateKey");
        }

        if (store.isCertificateEntry(keyName))
        {
            fail("key identified as certificate entry");
        }

        if (!store.isKeyEntry(keyName))
        {
            fail("key not identified as key entry");
        }

        Key storeKey = store.getKey(keyName, password);

        if (store.getType().equals("BCFKS"))
        {
            isTrue("", key.equals(storeKey));
        }

        if (password != null)
        {
             try
             {
                 store.getKey(keyName, null);
             }
             catch (UnrecoverableKeyException e)
             {
                 isTrue("",e.getMessage().startsWith("BCFKS KeyStore unable to recover private key (privkey)"));
             }
        }

        Certificate[] certificateChain = store.getCertificateChain(keyName);
        if (certificateChain == null)
        {
            fail("Did not return certificate chain");
        }
        isTrue("", cert.equals(certificateChain[0]));

        isTrue("", keyName.equals(store.getCertificateAlias(cert)));
    }

    private void certStorageCheck(KeyStore store, String certName, Certificate cert)
        throws KeyStoreException
    {
        if (!store.containsAlias(certName))
        {
            fail("couldn't find alias " + certName);
        }

        if (!store.isCertificateEntry(certName))
        {
            fail("cert not identified as certificate entry");
        }

        if (store.isKeyEntry(certName))
        {
            fail("cert identified as key entry");
        }

        if (!certName.equals(store.getCertificateAlias(cert)))
        {
            fail("Did not return alias for certificate entry");
        }
    }

    private void secretKeyStorageCheck(KeyStore store, String keyName, SecretKey key, char[] password)
        throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
    {
        if (!store.containsAlias(keyName))
        {
            fail("couldn't find alias privateKey");
        }

        if (store.isCertificateEntry(keyName))
        {
            fail("key identified as certificate entry");
        }

        if (!store.isKeyEntry(keyName))
        {
            fail("key not identified as key entry");
        }

        Key storeKey = store.getKey(keyName, password);

        isTrue("", Arrays.areEqual(key.getEncoded(), storeKey.getEncoded()));

        if (password != null)
        {
             try
             {
                 store.getKey(keyName, null);
             }
             catch (UnrecoverableKeyException e)
             {
                 isTrue("", e.getMessage().startsWith("BCFKS KeyStore unable to recover secret key (seckey)"));
             }
        }

        Certificate[] certificateChain = store.getCertificateChain(keyName);
        if (certificateChain != null)
        {
            fail("returned certificates!");
        }
    }

    public String getName()
    {
        return "BCFKS";
    }

    public void performTest()
        throws Exception
    {
        shouldCreateEmptyBCFKSNoPassword();
        shouldCreateEmptyBCFKSPassword();
        shouldStoreMultipleKeys();
        shouldStoreOneCertificate();
        shouldStoreOneECKeyWithChain();
        shouldStoreOnePrivateKey();
        shouldStoreOnePrivateKeyWithChain();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BCFKSStoreTest());
    }
}
