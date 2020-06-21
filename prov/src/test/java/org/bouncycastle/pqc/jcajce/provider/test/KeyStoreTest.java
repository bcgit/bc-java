package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;

public class KeyStoreTest
    extends TestCase
{
    private static final long ONE_DAY_IN_MILLIS = 24 * 60 * 60 * 1000;
    private static final long TEN_YEARS_IN_MILLIS = 10l * 365 * ONE_DAY_IN_MILLIS;

    private static Map algIds = new HashMap();

    static
    {
        algIds.put("SHA512WITHSPHINCS256", new AlgorithmIdentifier(BCObjectIdentifiers.sphincs256_with_SHA512));
        algIds.put("SHA256WITHXMSSMT", new AlgorithmIdentifier(BCObjectIdentifiers.xmss_mt_SHA256ph));
        algIds.put("SHA512WITHXMSSMT", new AlgorithmIdentifier(BCObjectIdentifiers.xmss_mt_SHA512ph));
    }

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public void testPKCS12()
        throws Exception
    {
        tryKeyStore("PKCS12");
        tryKeyStore("PKCS12-DEF");
    }

    public void testBKS()
        throws Exception
    {
        tryKeyStore("BKS");
        tryKeyStore("UBER");
    }

    public void testBCFKS()
        throws Exception
    {
        tryKeyStore("BCFKS-DEF");
    }

    private void tryKeyStore(String format)
        throws Exception
    {
        // Keystore to store certificates and private keys
        KeyStore store = KeyStore.getInstance(format, "BC");

        store.load(null, null);

        String password = "qwertz";
        // XMSS
        X500NameBuilder nameBuilder = new X500NameBuilder();

        nameBuilder.addRDN(BCStyle.CN, "Root CA");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();
        // root CA
        X509Certificate rootCA = createPQSelfSignedCert(nameBuilder.build(), "SHA256WITHXMSSMT", kp);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = rootCA;
        // store root private key
        String alias1 = "xmssmt private";
        store.setKeyEntry(alias1, kp.getPrivate(), password.toCharArray(), chain);
        // store root certificate
        store.setCertificateEntry("root ca", rootCA);

        // McEliece
        kpg = KeyPairGenerator.getInstance("McEliece", "BCPQC");

        McElieceKeyGenParameterSpec params = new McElieceKeyGenParameterSpec(9, 33);
        kpg.initialize(params);

        KeyPair mcelieceKp = kpg.generateKeyPair();

        ExtensionsGenerator extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.encipherOnly));

        X509Certificate cert1 = createCert(nameBuilder.build(), kp.getPrivate(), new X500Name("CN=meceliece"), "SHA256WITHXMSSMT",
            extGenerator.generate(), mcelieceKp.getPublic());

        X509Certificate[] chain1 = new X509Certificate[2];
        chain1[1] = rootCA;
        chain1[0] = cert1;

        // SPHINCS-256
        kpg = KeyPairGenerator.getInstance("SPHINCS256", "BCPQC");

        kpg.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA512_256));

        KeyPair sphincsKp = kpg.generateKeyPair();

        extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        X509Certificate cert2 = createCert(nameBuilder.build(), sphincsKp.getPrivate(), new X500Name("CN=sphincs256"), "SHA512WITHSPHINCS256",
            extGenerator.generate(), sphincsKp.getPublic());

        X509Certificate[] chain2 = new X509Certificate[2];
        chain2[1] = rootCA;
        chain2[0] = cert2;

        String alias2 = "private key 1";
        String alias3 = "private key 2";

        // store private keys
        store.setKeyEntry(alias2, mcelieceKp.getPrivate(), password.toCharArray(), chain1);
        store.setKeyEntry(alias3, sphincsKp.getPrivate(), password.toCharArray(), chain2);

        // store certificates
        store.setCertificateEntry("cert 1", cert1);
        store.setCertificateEntry("cert 2", cert2);

        // can't restore keys from keystore
        Key k1 = store.getKey(alias1, password.toCharArray());

        assertEquals(kp.getPrivate(), k1);

        Key k2 = store.getKey(alias2, password.toCharArray());

        assertEquals(mcelieceKp.getPrivate(), k2);

        Key k3 = store.getKey(alias3, password.toCharArray());

        assertEquals(sphincsKp.getPrivate(), k3);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store.store(bOut, "fred".toCharArray());

        KeyStore bcStore = KeyStore.getInstance(format, "BC");

        bcStore.load(new ByteArrayInputStream(bOut.toByteArray()), "fred".toCharArray());

        k1 = store.getKey(alias1, password.toCharArray());

        assertEquals(kp.getPrivate(), k1);

        k2 = store.getKey(alias2, password.toCharArray());

        assertEquals(mcelieceKp.getPrivate(), k2);

        k3 = store.getKey(alias3, password.toCharArray());

        assertEquals(sphincsKp.getPrivate(), k3);
    }

    private static X509Certificate createPQSelfSignedCert(X500Name dn, String sigName, KeyPair keyPair)
        throws Exception
    {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        long time = System.currentTimeMillis();
        AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());
        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(dn);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + TEN_YEARS_IN_MILLIS)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        ExtensionsGenerator extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

        certGen.setExtensions(extGenerator.generate());

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, BouncyCastlePQCProvider.PROVIDER_NAME);
        sig.initSign(keyPair.getPrivate());
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
            .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    private static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, X500Name dn, String sigName,
                                             Extensions extensions, PublicKey pubKey)
        throws Exception
    {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        long time = System.currentTimeMillis();
        AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());

        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(signerName);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + TEN_YEARS_IN_MILLIS)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));

        certGen.setExtensions(extensions);

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, BouncyCastlePQCProvider.PROVIDER_NAME);
        sig.initSign(signerKey);
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }
}
