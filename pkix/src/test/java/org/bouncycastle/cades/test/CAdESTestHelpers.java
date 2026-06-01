package org.bouncycastle.cades.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

/**
 * Shared helpers used by the CAdES tests &mdash; lazily-constructed local
 * TSA cert / key pair and a token-minting routine. Kept in its own
 * (test-only) class so multiple test classes don&apos;t each have to roll
 * their own TSA harness.
 */
final class CAdESTestHelpers
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final ASN1ObjectIdentifier TSA_POLICY = new ASN1ObjectIdentifier("1.2.3.4.5");

    private static KeyPair tsaKP;
    private static X509Certificate tsaCert;

    private CAdESTestHelpers()
    {
    }

    private static synchronized void init()
        throws Exception
    {
        if (tsaKP == null)
        {
            tsaKP = CMSTestUtil.makeKeyPair();
            tsaCert = makeTsaCert(tsaKP, "CN=Local TSA, C=AU");
        }
    }

    /** Build a TSA-suitable self-signed cert with critical timeStamping EKU. */
    static X509Certificate makeTsaCert(KeyPair kp, String dn)
        throws Exception
    {
        Date notBefore = new Date(System.currentTimeMillis() - 60000L);
        Date notAfter = new Date(System.currentTimeMillis() + 60L * 60000L);

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
            new X500Name(dn), BigInteger.valueOf(1),
            notBefore, notAfter,
            new X500Name(dn),
            kp.getPublic());

        b.addExtension(Extension.extendedKeyUsage, true,
            new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        ContentSigner s = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(s));
    }

    /**
     * Mint a TSA token over the given imprint using a shared, lazily
     * constructed local TSA key + cert.
     */
    static TimeStampToken mintTsaToken(byte[] imprint)
        throws Exception
    {
        init();

        DigestCalculator sha1 = new BcDigestCalculatorProvider().get(
            new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1));

        ContentSigner tsaSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(tsaKP.getPrivate());

        TimeStampTokenGenerator tsGen = new TimeStampTokenGenerator(
            new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
                .build(tsaSigner, tsaCert),
            sha1, TSA_POLICY);
        tsGen.addCertificates(new JcaCertStore(Collections.singletonList(tsaCert)));

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest req = reqGen.generate(TSPAlgorithms.SHA256, imprint, BigInteger.valueOf(100));

        TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(tsGen, TSPAlgorithms.ALLOWED);
        TimeStampResponse resp = respGen.generate(req, BigInteger.valueOf(23), new Date());
        return resp.getTimeStampToken();
    }
}
