package org.bouncycastle.cert.c509.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cbor.c509.C509CertificationRequest;
import org.bouncycastle.cbor.c509.C509PrivateKey;
import org.bouncycastle.cbor.c509.C509SignatureAlgorithm;
import org.bouncycastle.cbor.c509.COSEC509;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.c509.C509CertificateBuilder;
import org.bouncycastle.cert.c509.C509CertificateHolder;
import org.bouncycastle.cert.c509.C509CertificationRequestBuilder;
import org.bouncycastle.cert.c509.C509CertificationRequestHolder;
import org.bouncycastle.cert.c509.bc.BcC509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.c509.jcajce.JcaC509CertificateConverter;
import org.bouncycastle.cert.c509.jcajce.JcaC509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Arrays;

/**
 * End to end tests for the C509 holder, builder and verifier provider classes: a
 * natively signed (type 2) certificate and certification request are issued and
 * verified through both the JCA/JCE and the lightweight operator paths, and an X.509
 * certificate issued in the usual way round-trips through the type 3 re-encoding.
 */
public class C509CertTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private KeyPair generateECKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        kpGen.initialize(new ECGenParameterSpec("P-256"), new SecureRandom());
        return kpGen.generateKeyPair();
    }

    public void testNativeCertificateBuildAndVerify()
        throws Exception
    {
        KeyPair issuerKp = generateECKeyPair();
        KeyPair subjectKp = generateECKeyPair();

        X500Name issuer = new X500Name("CN=C509 test CA");
        X500Name subject = new X500Name("CN=C509 test EE");
        Date notBefore = new Date((System.currentTimeMillis() / 1000) * 1000);
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC")
            .build(issuerKp.getPrivate());

        C509CertificateHolder cert = new C509CertificateBuilder(issuer, BigInteger.valueOf(0x1F50D),
            notBefore, notAfter, subject,
            SubjectPublicKeyInfo.getInstance(subjectKp.getPublic().getEncoded()))
            .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature))
            .build(signer);

        assertEquals(C509Certificate.TYPE_NATIVE, cert.getCertificateType());
        assertEquals(BigInteger.valueOf(0x1F50D), cert.getSerialNumber());
        assertEquals(issuer, cert.getIssuer());
        assertEquals(subject, cert.getSubject());
        assertEquals(Integer.valueOf(C509SignatureAlgorithm.ECDSA_WITH_SHA256),
            cert.getSignatureAlgorithm().getRegistryValue());
        assertTrue(cert.isValidOn(new Date(notBefore.getTime() + 1000)));
        assertNotNull(cert.getExtensions().getExtension(Extension.keyUsage));

        // verification through the JCA/JCE path
        assertTrue(cert.isSignatureValid(new JcaC509ContentVerifierProviderBuilder().setProvider("BC")
            .build(SubjectPublicKeyInfo.getInstance(issuerKp.getPublic().getEncoded()))));

        // verification through the lightweight path
        assertTrue(cert.isSignatureValid(new BcC509ContentVerifierProviderBuilder()
            .build(SubjectPublicKeyInfo.getInstance(issuerKp.getPublic().getEncoded()))));

        // a corrupted encoding must not verify
        byte[] encoding = cert.getEncoded();
        byte[] tampered = Arrays.clone(encoding);
        tampered[tampered.length - 1] ^= 1;
        C509CertificateHolder tamperedCert = new C509CertificateHolder(tampered);
        assertFalse(tamperedCert.isSignatureValid(new JcaC509ContentVerifierProviderBuilder()
            .setProvider("BC").build(SubjectPublicKeyInfo.getInstance(issuerKp.getPublic().getEncoded()))));

        // parse and re-encode is the identity
        assertTrue(Arrays.areEqual(encoding, new C509CertificateHolder(encoding).getEncoded()));

        // the native key uses a compressed point (0x02/0x03) by default
        int firstKeyByte = cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()[0] & 0xFF;
        assertTrue(firstKeyByte == 0x02 || firstKeyByte == 0x03);

        // a natively signed certificate has no X.509 form
        try
        {
            cert.getC509Certificate().toX509Certificate();
            fail("native certificate produced an X.509 view");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        // COSE_C509 wrapping round-trips
        byte[] coseC509 = COSEC509.encode(new C509Certificate[]{ cert.getC509Certificate() });
        C509Certificate[] decoded = COSEC509.decode(coseC509);
        assertEquals(1, decoded.length);
        assertTrue(Arrays.areEqual(encoding, decoded[0].getEncoded()));
    }

    public void testPkinitExtendedKeyUsage()
        throws Exception
    {
        // the RFC 4556 PKINIT extended key usages are registry values 10 and 11 in the
        // C509 EKU table, so they must compress to the specific form and come back
        // byte-identically through both certificate types
        KeyPair issuerKp = generateECKeyPair();
        KeyPair subjectKp = generateECKeyPair();

        Date notBefore = new Date((System.currentTimeMillis() / 1000) * 1000);
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        org.bouncycastle.asn1.x509.ExtendedKeyUsage eku = new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
            new org.bouncycastle.asn1.x509.KeyPurposeId[]{
                org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_pkinitClientAuth,
                org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_pkinitKdc });

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC")
            .build(issuerKp.getPrivate());

        // native (type 2): the specific EKU encoding is mandatory there
        C509CertificateHolder nativeCert = new C509CertificateBuilder(new X500Name("CN=PKINIT CA"),
            BigInteger.valueOf(7), notBefore, notAfter, new X500Name("CN=PKINIT client"),
            SubjectPublicKeyInfo.getInstance(subjectKp.getPublic().getEncoded()))
            .addExtension(Extension.extendedKeyUsage, false, eku)
            .build(signer);

        assertTrue(Arrays.areEqual(eku.getEncoded(),
            org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(
                nativeCert.getExtensions().getExtensionParsedValue(Extension.extendedKeyUsage)).getEncoded()));
        assertTrue(nativeCert.isSignatureValid(new JcaC509ContentVerifierProviderBuilder().setProvider("BC")
            .build(SubjectPublicKeyInfo.getInstance(issuerKp.getPublic().getEncoded()))));

        // re-encoded (type 3): the whole certificate must reconstruct byte for byte
        X509CertificateHolder x509 = new X509v3CertificateBuilder(new X500Name("CN=PKINIT CA"),
            BigInteger.valueOf(8), notBefore, notAfter, new X500Name("CN=PKINIT client"),
            SubjectPublicKeyInfo.getInstance(subjectKp.getPublic().getEncoded()))
            .addExtension(Extension.extendedKeyUsage, false, eku)
            .build(signer);

        byte[] der = x509.getEncoded();
        C509Certificate c509 = C509Certificate.fromX509Certificate(der);
        assertTrue(Arrays.areEqual(der, c509.toX509Certificate().getEncoded(ASN1Encoding.DER)));
    }

    public void testX509RoundTripThroughType3()
        throws Exception
    {
        KeyPair issuerKp = generateECKeyPair();
        KeyPair subjectKp = generateECKeyPair();

        Date notBefore = new Date((System.currentTimeMillis() / 1000) * 1000);
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        X509CertificateHolder x509 = new X509v3CertificateBuilder(new X500Name("CN=C509 test CA"),
            BigInteger.valueOf(4711), notBefore, notAfter, new X500Name("CN=C509 test EE"),
            SubjectPublicKeyInfo.getInstance(subjectKp.getPublic().getEncoded()))
            .addExtension(extGen.getExtension(Extension.keyUsage))
            .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(issuerKp.getPrivate()));

        byte[] der = x509.getEncoded();
        C509Certificate c509 = C509Certificate.fromX509Certificate(der);
        assertEquals(C509Certificate.TYPE_REENCODED_X509, c509.getCertificateType());

        // reconstruction is byte identical, so the original signature verifies
        byte[] rebuilt = c509.toX509Certificate().getEncoded(ASN1Encoding.DER);
        assertTrue(Arrays.areEqual(der, rebuilt));

        C509CertificateHolder holder = new C509CertificateHolder(c509);
        assertTrue(holder.isSignatureValid(new JcaC509ContentVerifierProviderBuilder().setProvider("BC")
            .build(SubjectPublicKeyInfo.getInstance(issuerKp.getPublic().getEncoded()))));

        // and converts to a JCA certificate that verifies with the issuer key
        X509Certificate jcaCert = new JcaC509CertificateConverter().setProvider("BC")
            .getCertificate(holder);
        jcaCert.verify(issuerKp.getPublic());
        assertTrue(Arrays.areEqual(der, jcaCert.getEncoded()));

        // the C509 forms produced directly and via the JCA holder agree
        assertTrue(Arrays.areEqual(c509.getEncoded(),
            C509Certificate.fromX509Certificate(Certificate.getInstance(der),
                org.bouncycastle.cbor.c509.C509ConversionOptions.DEFAULT).getEncoded()));

        // holder round trip through JcaX509CertificateHolder
        assertTrue(Arrays.areEqual(der, new JcaX509CertificateHolder(jcaCert).getEncoded()));
    }

    public void testNativeCertificationRequestBuildAndVerify()
        throws Exception
    {
        KeyPair subjectKp = generateECKeyPair();

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
        Extensions extensionRequest = extGen.generate();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC")
            .build(subjectKp.getPrivate());

        C509CertificationRequestHolder csr = new C509CertificationRequestBuilder(
            new X500Name("CN=C509 test EE"),
            SubjectPublicKeyInfo.getInstance(subjectKp.getPublic().getEncoded()))
            .setExtensionRequest(extensionRequest)
            .setChallengePassword("secret1234")
            .build(signer);

        assertEquals(C509CertificationRequest.TYPE_NATIVE, csr.getRequestType());
        assertEquals(new X500Name("CN=C509 test EE"), csr.getSubject());
        assertEquals(2, csr.getAttributes().length);

        // the proof-of-possession verifies with the subject public key, both paths
        assertTrue(csr.isSignatureValid(new JcaC509ContentVerifierProviderBuilder().setProvider("BC")
            .build(csr.getSubjectPublicKeyInfo())));
        assertTrue(csr.isSignatureValid(new BcC509ContentVerifierProviderBuilder()
            .build(csr.getSubjectPublicKeyInfo())));

        // re-encode identity
        byte[] encoding = csr.getEncoded();
        assertTrue(Arrays.areEqual(encoding, new C509CertificationRequestHolder(encoding).getEncoded()));

        // extension request survives the keyUsage int compaction in the attribute value
        C509CertificationRequestHolder parsed = new C509CertificationRequestHolder(encoding);
        assertEquals(Integer.valueOf(0), parsed.getAttributes()[0].getRegistryValue());
    }

    public void testPKCS10RoundTripThroughType3()
        throws Exception
    {
        KeyPair subjectKp = generateECKeyPair();

        // build a PKCS#10 request via the C509 native builder's DER cousin: use the
        // JCA classes directly to get a DER request with an extensionRequest
        org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder p10Builder =
            new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                new javax.security.auth.x500.X500Principal("CN=C509 test EE"), subjectKp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
        p10Builder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
            extGen.generate());
        org.bouncycastle.pkcs.PKCS10CertificationRequest p10 = p10Builder
            .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(subjectKp.getPrivate()));

        byte[] der = p10.getEncoded();
        C509CertificationRequest c509 = C509CertificationRequest.fromCertificationRequest(der);
        assertEquals(C509CertificationRequest.TYPE_REENCODED_PKCS10, c509.getRequestType());

        byte[] rebuilt = c509.toCertificationRequest().getEncoded(ASN1Encoding.DER);
        assertTrue(Arrays.areEqual(der, rebuilt));

        // the copied signature verifies over the reconstructed DER
        C509CertificationRequestHolder holder = new C509CertificationRequestHolder(c509);
        assertTrue(holder.isSignatureValid(new JcaC509ContentVerifierProviderBuilder().setProvider("BC")
            .build(holder.getSubjectPublicKeyInfo())));
    }

    public void testPrivateKeyStructure()
        throws Exception
    {
        KeyPair kp = generateECKeyPair();
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        C509PrivateKey key = C509PrivateKey.fromPrivateKeyInfo(pkInfo);
        assertEquals(C509PrivateKey.TYPE_ASYMMETRIC_KEY_PACKAGE, key.getPrivateKeyType());

        byte[] encoding = key.getEncoded();
        C509PrivateKey parsed = C509PrivateKey.getInstance(encoding);
        assertEquals(key, parsed);
        assertTrue(Arrays.areEqual(encoding, parsed.getEncoded()));

        // the PrivateKeyInfo view carries the same key material
        assertTrue(Arrays.areEqual(pkInfo.getPrivateKey().getOctets(),
            parsed.toPrivateKeyInfo().getPrivateKey().getOctets()));

        // destroy zeroizes and disables the accessors
        parsed.destroy();
        assertTrue(parsed.isDestroyed());
        try
        {
            parsed.getEncoded();
            fail("destroyed key still encodable");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }
}
