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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.bc.EncryptedObjectStoreData;
import org.bouncycastle.asn1.bc.ObjectStore;
import org.bouncycastle.asn1.bc.ObjectStoreIntegrityCheck;
import org.bouncycastle.asn1.bc.PbkdMacIntegrityCheck;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.crypto.util.PBKDFConfig;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jcajce.BCFKSStoreParameter;
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

    static byte[] kwpKeyStore = Base64.decode(
        "MIIJ/TCCCT8wgZUGCSqGSIb3DQEFDTCBhzBlBgkqhkiG9w0BBQwwWARAKXQjiKdsRc8lgCbMh8wLqjNPCiLcXVxArXA4/n6Y72G8jn" +
            "jWUsXqvMQFmruTbQF6USSVaMgS1UlTbdLtu7yH9wIDAMgAAgEgMAwGCCqGSIb3DQILBQAwHgYJYIZIAWUDBAEvMBEEDJMoeNdAkcnM" +
            "QjtxowIBCASCCKMU5dCIAkTb84CUiUGy4no3nGgVZL+2t4MNPKhMiL+2Xv7Ok9rucD2SMitzm+kxnkVU+aYGLVUrwEPFCvq5GWdnzO" +
            "yjCd3XzTieySlfxhIxYMixGfz8NAvPu+P2LwtE+j2C4poHS7+MG22OXpxTTLGzWGuYusxb1zVLTujP6gSVGbtBikLxOXRiYXapZQzL" +
            "32bOIKV/tHLv3JCKvIGyJAnTQBDlHQxVsm8fcYBhc101qc9vd3qMborJEZK3E+znJ++lI0yIb+WcZJ3PDI11Fzf22M1D6qtV8RELsL" +
            "b5zfLheFLc4rJcY0YSja24se0tFvT7X9cSyrpvXdNDmzBlBThPdINsKPf3N6fO/9ibn/0QIJPY5bQc3SwbN8c7vboHOJzbWjq7n7Q7" +
            "1ZkFeiYO/NIXKZ4/KN8sqlRLjvEy4BFnbGoufim+K1zpFGdUPbYpDkuzCkfQfiEaQ9Zt69p5w5e6qh04kgHue0Ac/0IsnRIFy78k4J" +
            "lK5TlrB3exqpuISZEWP72WDa+0yTaRM6ecMfIqieDNQmpD9U3HpmdMgiWZXTpCTtM/3I62Bv7EkwcVccRP9z4QUcoGZy81EemQ4d3e" +
            "OVfYgvgZBCsbSpf+V8HlsnApTbJubTY1wJQAA19h49E7l3VCxSmeNcUSSE68xJjdJPPAzU1v83+RkYUDPlRx1YsO77zYBSuOwJr0g4" +
            "BDTfnyd1vZCM6APt9N7Z2MfALoSSg4EF68nr144GLAMZw4ZVjfUeZ+kF3mjTDPujOoyI3vDztA5ZFa0JCQpp8Yh0CuO+sGnWLh+7Tb" +
            "irH2ifEscmNI++csUwDPSInjfGzv722JY6c9XzbaqDGqstpykwwUVN01IceolCvgeHZW7P0feDyqbpgmpdRxiGuBWshFEdcttXDSl9" +
            "mQVEyYAMHQFVQKIx2RrFD7QPWZhITGqCvF44GNst/3962Au9oyGAY6rRQfN/HdF4+ygWjOS0t/50c1eAyBj1Rfk/M4sHBi8dKDjOpX" +
            "QzqfqLqHjevxQPw1761q629iTagOO/3AIebbraD2qLqDHjmqUAW0ZVLkdS5n8zYyiqGsVeKok7SSDDKQfqwouPHJvRmKzHAK6bZDdr" +
            "qMBqNfNcRghWHSH0jM4j8G1w3H2FQsNfBHqTb+kiFx1jEovKkf2HumctWwI5hqV2R2I23ThRNQbh6bdtFc8D3a8YnuXpUK+Tw/RTzM" +
            "eGtUsVeakGOZDHh9AlxsdcLChY9xTLMzbpLfb6VAE9kpZ86Uwe60i+S4ropyIp5cwXizAgJPh1T51ZWTzEu+s8BDEAkXSDgxs1PFML" +
            "Ha2pWnHPMNSs4VF6eeyK0Vj66m4LcQ0AgE35jAGxWQm31KbWI/h8EMxiC/tDJfMJ3UUKxYCRdbcneDBRc4E4cNmZVqajc8o9Fexr97" +
            "GLQ6Is1HVoG65qtq6I9Wt6wmA/5i8ptG7bl7NrIzn3Fg0bMbwHEaKIoXrFHTM0EjwnOkVtQWBNDhnBa66IDJXMxJzXDB2uoMU/wX2y" +
            "4dGpM+mgomJt0U3i29HqeihEQjHDc0hTJLkp2SJ2tKw3+VtoXUinV1W7tsG9TMj3F+XNSeiGFrcZpryi6+Fml3Tohg/FaiJQLpB9pL" +
            "tzNd61ln1Q6RTHcOMChNocCRaagH6ntX5j8GcVp0auPfw8zyR5iNGueQdnV38Q6MhiGxlMQKC/gjBdKAHRI2q+31tGK8ZslHFxDee1" +
            "fy3wtRZpLDwgecH74g4+1TYTLPj/PNeYRQicRCa1BbvI3zB1d8t+LKTg/f34MeEzdMpRT8fRb6vw/O1CRhtdl/0pBQ7RZQSrZFPdEr" +
            "KPRv4/1IG46crTCw1/AOMTXKjPeaUeADjff7aLKizJHUSPr6sTRxoMWQeOYfBDnRiLDZ/XYvSDkjnzesa0hdQIIe/tHnqSZ23Jbi46" +
            "bLD7Lhf3lfZzbEOqKXAlq0m/ooidubndc0K1xVex4M/T+M0mMPRwO0uICJM4EtivU9Fp5/12GXdvimGEhr/adGodf+JduhsUoIUiz5" +
            "TghRV0dSuLtQkcD2d0GkfxgHkCBlhbS3WifMWLTa3lHWrCVyhdIf6m5UOtqfzj5CEEkwE+L6urNBo3D4zHUjm8XJekjI3xjGbQHjBo" +
            "sr+BFHkwGNfTXXBHVqRE0L8lH6kSpLaCF5iMpU2NuAeaJ/xdS7LUXBtn4Zvi34PR3/akwMYIr4X+uDM0eB0KkOyyqSXZVPsT7uGMef" +
            "wOHmbx1eHe22mR/q1r1iczDwOtXNYo8OB9jSsL3XWFdt4STxdA7kFEsAvK001x0pjrpTa/j/4ixjKhBGu8V/WVuBl0Hlicybtdl7xF" +
            "CgoeF3FrAsn2Rw0EjVJm4uLpdEHGIVCWWTgadhZ9YyMWoMenLOUoGMlWXGE9hLGUfJG1wOMlFg33zq4dwCj17O0ULdpHh7QFQFEEpM" +
            "+zscDhOHKmrZZEuiJvhR0JFkZz2rml0TEfSjCmdQ8XfJMzLbQ8BKZhWLOQdVh8Scn96Hm0EGkFBkcb4dO/Ubw+cu+bGskxHL1Q6uW0" +
            "hGOdejiS7yWclE//uzSlSTa7GRtZ1F/vziWIVno0IInEyiOsCGagagWmxMvv1GTnRJwJl8Bt0BPJmWS2L4CClD6ocH2DrCEEYjMraP" +
            "dquGbe0/0eYv3qANDWjvzJs4o4/4SoKZuRBuVj5YQMs69XdaxPgnC3Xfx59pf1Q5qOQe94R8oVTnT6z6G1Radsoweh1UnwItjjt4pt" +
            "pfjyUn4bF2Ovz6bs/Tprbo2B4gmBraimCVHT5pruScBY2q4Vd8XiGbiviS8SgqUnxhH/4XmRRdeYpHpZyet1DT+nNTdJdOCfrsE630" +
            "9CEQNhQRXt9j5c9S8fnwEA3x/FsriCOAnXsmjVZTnMmctnEYs0aChPxnCBgW1vb2dVUTJQ+KR+2CD3xPNiIEwdk9rA+80k1z3JXek8" +
            "tac4cwgbcwDAYIKoZIhvcNAgsFADBlBgkqhkiG9w0BBQwwWARAvH3U5H5R/XeTJYthNF/5aUAsqnHPEeperLR1iXVAiVH8t4iby2WP" +
            "FbvQtoKDbREOo9NaULKIWlDlimxCJosvygIDAMgAAgFAMAwGCCqGSIb3DQILBQAEQGeIvocQlW6yjPCczqj+yNdn6sTcmuHI9AnFtn" +
            "aY0K7Ki2oIlXl5D9TLznFhJuHDtrIA3VYy2XTCvyrY3qEIySo=");

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

        checkOnePrivateKeyFips(privKey, new X509Certificate[]{cert}, null);
        checkOnePrivateKeyFips(privKey, new X509Certificate[]{cert}, testPassword);
        checkOnePrivateKeyDef(privKey, new X509Certificate[]{cert}, null);
        checkOnePrivateKeyDef(privKey, new X509Certificate[]{cert}, testPassword);
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

        isTrue("", 4 == store2.size());

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

        isTrue("", null == store2.getCertificate("unknown"));

        isTrue("", null == store2.getCertificateChain("unknown"));

        isTrue("", !store2.isCertificateEntry("unknown"));

        isTrue("", !store2.isKeyEntry("unknown"));

        isTrue("", !store2.containsAlias("unknown"));
    }

    public void shouldParseKWPKeyStore()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(trustedCertData));

        SecretKeySpec aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "AES");
        SecretKeySpec edeKey = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "DESede");

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(kwpKeyStore), testPassword);

        isTrue("", 4 == store2.size());

        Key storeDesEde = store2.getKey("secret2", "secretPwd2".toCharArray());

        isTrue("", edeKey.getAlgorithm().equals(storeDesEde.getAlgorithm()));

        isTrue("", Arrays.areEqual(edeKey.getEncoded(), storeDesEde.getEncoded()));

        Key storeAes = store2.getKey("secret1", "secretPwd1".toCharArray());
        isTrue("", Arrays.areEqual(aesKey.getEncoded(), storeAes.getEncoded()));
        isTrue("", aesKey.getAlgorithm().equals(storeAes.getAlgorithm()));

        Key storePrivKey = store2.getKey("privkey", testPassword);
        isTrue("", 2 == store2.getCertificateChain("privkey").length);
        isTrue("", storePrivKey instanceof RSAPrivateCrtKey);

        Certificate storeCert = store2.getCertificate("trusted");
        isTrue("", cert.equals(storeCert));

        isTrue("", null == store2.getCertificate("unknown"));

        isTrue("", null == store2.getCertificateChain("unknown"));

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

        SecretKeySpec camellia128 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "Camellia");
        SecretKeySpec camellia192 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f0001020304050607"), "Camellia");
        SecretKeySpec camellia256 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "Camellia");
        SecretKeySpec seed = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "SEED");
        SecretKeySpec aria128 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "ARIA");
        SecretKeySpec aria192 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f0001020304050607"), "ARIA");
        SecretKeySpec aria256 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "ARIA");

        store1.setKeyEntry("secret1", aesKey, "secretPwd1".toCharArray(), null);
        store1.setKeyEntry("secret2", edeKey1, "secretPwd2".toCharArray(), null);
        store1.setKeyEntry("secret3", edeKey2, "secretPwd3".toCharArray(), null);
        store1.setKeyEntry("secret4", edeKey3, "secretPwd4".toCharArray(), null);
        store1.setKeyEntry("secret5", hmacKey1, "secretPwd5".toCharArray(), null);
        store1.setKeyEntry("secret6", hmacKey224, "secretPwd6".toCharArray(), null);
        store1.setKeyEntry("secret7", hmacKey256, "secretPwd7".toCharArray(), null);
        store1.setKeyEntry("secret8", hmacKey384, "secretPwd8".toCharArray(), null);
        store1.setKeyEntry("secret9", hmacKey512, "secretPwd9".toCharArray(), null);

        store1.setKeyEntry("secret10", camellia128, "secretPwd10".toCharArray(), null);
        store1.setKeyEntry("secret11", camellia192, "secretPwd11".toCharArray(), null);
        store1.setKeyEntry("secret12", camellia256, "secretPwd12".toCharArray(), null);
        store1.setKeyEntry("secret13", seed, "secretPwd13".toCharArray(), null);
        store1.setKeyEntry("secret14", aria128, "secretPwd14".toCharArray(), null);
        store1.setKeyEntry("secret15", aria192, "secretPwd15".toCharArray(), null);
        store1.setKeyEntry("secret16", aria256, "secretPwd16".toCharArray(), null);

        checkSecretKey(store1, "secret1", "secretPwd1".toCharArray(), aesKey);
        checkSecretKey(store1, "secret2", "secretPwd2".toCharArray(), edeKey1); // TRIPLEDES and TDEA will convert to DESEDE
        checkSecretKey(store1, "secret3", "secretPwd3".toCharArray(), edeKey1);
        checkSecretKey(store1, "secret4", "secretPwd4".toCharArray(), edeKey1);
        // TODO:
//        checkSecretKey(store1, "secret5", "secretPwd5".toCharArray(), hmacKey1);
//        checkSecretKey(store1, "secret6", "secretPwd6".toCharArray(), hmacKey224);
//        checkSecretKey(store1, "secret7", "secretPwd7".toCharArray(), hmacKey256);
//        checkSecretKey(store1, "secret8", "secretPwd8".toCharArray(), hmacKey384);
//        checkSecretKey(store1, "secret9", "secretPwd9".toCharArray(), hmacKey512);

        checkSecretKey(store1, "secret10", "secretPwd10".toCharArray(), camellia128);
        checkSecretKey(store1, "secret11", "secretPwd11".toCharArray(), camellia192);
        checkSecretKey(store1, "secret12", "secretPwd12".toCharArray(), camellia256);
        checkSecretKey(store1, "secret13", "secretPwd13".toCharArray(), seed);
        checkSecretKey(store1, "secret14", "secretPwd14".toCharArray(), aria128);
        checkSecretKey(store1, "secret15", "secretPwd15".toCharArray(), aria192);
        checkSecretKey(store1, "secret16", "secretPwd16".toCharArray(), aria256);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store1.store(bOut, "secretkeytest".toCharArray());

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), "secretkeytest".toCharArray());

        checkSecretKey(store2, "secret1", "secretPwd1".toCharArray(), aesKey);
        checkSecretKey(store2, "secret2", "secretPwd2".toCharArray(), edeKey1); // TRIPLEDES and TDEA will convert to DESEDE
        checkSecretKey(store2, "secret3", "secretPwd3".toCharArray(), edeKey1);
        checkSecretKey(store2, "secret4", "secretPwd4".toCharArray(), edeKey1);
        // TODO:
//        checkSecretKey(store2, "secret5", "secretPwd5".toCharArray(), hmacKey1);
//        checkSecretKey(store2, "secret6", "secretPwd6".toCharArray(), hmacKey224);
//        checkSecretKey(store2, "secret7", "secretPwd7".toCharArray(), hmacKey256);
//        checkSecretKey(store2, "secret8", "secretPwd8".toCharArray(), hmacKey384);
//        checkSecretKey(store2, "secret9", "secretPwd9".toCharArray(), hmacKey512);

        isTrue("", null == store2.getKey("secret17", new char[0]));
    }

    public void shouldFailOnWrongPassword()
        throws Exception
    {
        failOnWrongPasswordTest("BCSFKS");
        failOnWrongPasswordTest("BCSFKS-DEF");
    }

    public void failOnWrongPasswordTest(String storeName)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(512);

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withRSA", kp2);
        X509Certificate interCert = TestUtils.createCert(
            X500Name.getInstance(finalCert.getSubjectX500Principal().getEncoded()),
            kp2.getPrivate(),
            "CN=EE",
            "SHA1withRSA",
            null,
            kp1.getPublic());

        KeyStore store1 = KeyStore.getInstance(storeName, "BC");

        store1.load(null, null);

        store1.setKeyEntry("privkey", kp1.getPrivate(), testPassword, new X509Certificate[]{interCert, finalCert});

        isTrue("privKey test 1", store1.getKey("privkey", testPassword) != null);

        try
        {
            store1.getKey("privkey", invalidTestPassword);
            fail("no exception");
        }
        catch (UnrecoverableKeyException e)
        {
            isEquals("wrong message, got : " + e.getMessage(), "unable to recover key (privkey)", e.getMessage());
        }

        isTrue("privKey test 2", store1.getKey("privkey", testPassword) != null);
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
        if (!store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class))
        {
            fail("not identified as key entry via SecretKeyEntry");
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
                isTrue("", e.getMessage().startsWith("BCFKS KeyStore unable to recover private key (privkey)"));
            }
        }

        Certificate[] certificateChain = store.getCertificateChain(keyName);
        if (certificateChain == null)
        {
            fail("Did not return certificate chain");
        }
        isTrue("", cert.equals(certificateChain[0]));

        isTrue("", keyName.equals(store.getCertificateAlias(cert)));

        if (store.entryInstanceOf(keyName, KeyStore.TrustedCertificateEntry.class))
        {
            fail("identified as TrustedCertificateEntry");
        }

        if (!store.entryInstanceOf(keyName, KeyStore.PrivateKeyEntry.class))
        {
            fail("not identified as key entry via PrivateKeyEntry");
        }

        if (store.entryInstanceOf(keyName, KeyStore.SecretKeyEntry.class))
        {
            fail("identified as key entry via SecretKeyEntry");
        }
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

        if (!store.entryInstanceOf(certName, KeyStore.TrustedCertificateEntry.class))
        {
            fail("cert not identified as TrustedCertificateEntry");
        }

        if (store.entryInstanceOf(certName, KeyStore.PrivateKeyEntry.class))
        {
            fail("cert identified as key entry via PrivateKeyEntry");
        }

        if (store.entryInstanceOf(certName, KeyStore.SecretKeyEntry.class))
        {
            fail("cert identified as key entry via SecretKeyEntry");
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

        if (store.entryInstanceOf(keyName, KeyStore.TrustedCertificateEntry.class))
        {
            fail("identified as TrustedCertificateEntry");
        }

        if (store.entryInstanceOf(keyName, KeyStore.PrivateKeyEntry.class))
        {
            fail("identified as key entry via PrivateKeyEntry");
        }

        if (!store.entryInstanceOf(keyName, KeyStore.SecretKeyEntry.class))
        {
            fail("not identified as key entry via SecretKeyEntry");
        }
    }

    private void shouldStoreUsingSCRYPT()
        throws Exception
    {
        byte[] enc = doStoreUsingStoreParameter(new ScryptConfig.Builder(1024, 8, 1)
                                                        .withSaltLength(20).build());

        ObjectStore store = ObjectStore.getInstance(enc);

        ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();

        isEquals(integrityCheck.getType(), ObjectStoreIntegrityCheck.PBKD_MAC_CHECK);

        PbkdMacIntegrityCheck check = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

        isTrue("wrong MAC", check.getMacAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.id_hmacWithSHA512));
        isTrue("wrong PBE", check.getPbkdAlgorithm().getAlgorithm().equals(MiscObjectIdentifiers.id_scrypt));

        ScryptParams sParams = ScryptParams.getInstance(check.getPbkdAlgorithm().getParameters());

        isEquals(20, sParams.getSalt().length);
        isEquals(1024, sParams.getCostParameter().intValue());
        isEquals(8, sParams.getBlockSize().intValue());
        isEquals(1, sParams.getParallelizationParameter().intValue());

        EncryptedObjectStoreData objStore = EncryptedObjectStoreData.getInstance(store.getStoreData());

        AlgorithmIdentifier encryptionAlgorithm = objStore.getEncryptionAlgorithm();
        isTrue(encryptionAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBES2));

        PBES2Parameters pbeParams = PBES2Parameters.getInstance(encryptionAlgorithm.getParameters());

        isTrue(pbeParams.getKeyDerivationFunc().getAlgorithm().equals(MiscObjectIdentifiers.id_scrypt));

        sParams = ScryptParams.getInstance(pbeParams.getKeyDerivationFunc().getParameters());

        isEquals(20, sParams.getSalt().length);
        isEquals(1024, sParams.getCostParameter().intValue());
        isEquals(8, sParams.getBlockSize().intValue());
        isEquals(1, sParams.getParallelizationParameter().intValue());
    }

    private void shouldStoreUsingPBKDF2()
        throws Exception
    {
        doStoreUsingPBKDF2(PBKDF2Config.PRF_SHA512);
        doStoreUsingPBKDF2(PBKDF2Config.PRF_SHA3_512);
    }

    private void doStoreUsingPBKDF2(AlgorithmIdentifier prf)
        throws Exception
    {
        byte[] enc = doStoreUsingStoreParameter(new PBKDF2Config.Builder()
                                                        .withPRF(prf)
                                                        .withIterationCount(1024)
                                                        .withSaltLength(20).build());

        ObjectStore store = ObjectStore.getInstance(enc);

        ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();

        isEquals(integrityCheck.getType(), ObjectStoreIntegrityCheck.PBKD_MAC_CHECK);

        PbkdMacIntegrityCheck check = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

        isTrue("wrong MAC", check.getMacAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.id_hmacWithSHA512));
        isTrue("wrong PBE", check.getPbkdAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.id_PBKDF2));

        PBKDF2Params pParams = PBKDF2Params.getInstance(check.getPbkdAlgorithm().getParameters());

        isTrue(pParams.getPrf().equals(prf));
        isEquals(20, pParams.getSalt().length);
        isEquals(1024, pParams.getIterationCount().intValue());

        EncryptedObjectStoreData objStore = EncryptedObjectStoreData.getInstance(store.getStoreData());

        AlgorithmIdentifier encryptionAlgorithm = objStore.getEncryptionAlgorithm();
        isTrue(encryptionAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBES2));

        PBES2Parameters pbeParams = PBES2Parameters.getInstance(encryptionAlgorithm.getParameters());

        isTrue(pbeParams.getKeyDerivationFunc().getAlgorithm().equals(PKCSObjectIdentifiers.id_PBKDF2));

        pParams = PBKDF2Params.getInstance(check.getPbkdAlgorithm().getParameters());

        isTrue(pParams.getPrf().equals(prf));
        isEquals(20, pParams.getSalt().length);
        isEquals(1024, pParams.getIterationCount().intValue());
    }

    private byte[] doStoreUsingStoreParameter(PBKDFConfig config)
        throws Exception
    {
        X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(trustedCertData));

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

        store1.store(new BCFKSStoreParameter(bOut, config, testPassword));

        KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), testPassword);

        isTrue("", entryDate.equals(store2.getCreationDate("cert")));
        isTrue("", 1 == store2.size());
        Enumeration<String> en2 = store2.aliases();

        isTrue("", "cert".equals(en2.nextElement()));
        isTrue("", !en2.hasMoreElements());

        certStorageCheck(store2, "cert", cert);

        // check invalid load with content

        checkInvalidLoad(store2, testPassword, bOut.toByteArray());

        // check deletion on purpose

        store1.deleteEntry("cert");

        isTrue("", 0 == store1.size());
        isTrue("", !store1.aliases().hasMoreElements());

        bOut = new ByteArrayOutputStream();

        store1.store(bOut, testPassword);

        store2 = KeyStore.getInstance("BCFKS", "BC");

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), testPassword);

        isTrue("", 0 == store2.size());
        isTrue("", !store2.aliases().hasMoreElements());

        return bOut.toByteArray();
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
        shouldStoreOneSecretKey();
        shouldStoreSecretKeys();
        shouldStoreUsingSCRYPT();
        shouldStoreUsingPBKDF2();
        shouldFailOnWrongPassword();
        shouldParseKWPKeyStore();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BCFKSStoreTest());
    }
}
