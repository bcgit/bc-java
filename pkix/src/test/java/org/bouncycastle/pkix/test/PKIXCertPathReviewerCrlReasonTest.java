package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A CRL entry's reasonCode is attacker-controlled: an out-of-range or beyond-int value must be
 * reported by the cert path reviewers as an "unknown" revocation reason, not escape as an
 * ArrayIndexOutOfBoundsException / ArithmeticException from indexing the reason table. Covers
 * both reviewer twins - org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer and the legacy
 * org.bouncycastle.x509.PKIXCertPathReviewer, which had drifted apart on this guard.
 */
public class PKIXCertPathReviewerCrlReasonTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testOutOfRangeReasonCodePkixReviewer()
        throws Exception
    {
        checkReviewers(BigInteger.valueOf(200));
    }

    public void testBeyondIntReasonCode()
        throws Exception
    {
        checkReviewers(new BigInteger("99999999999999999999"));
    }

    private void checkReviewers(BigInteger reasonCode)
        throws Exception
    {
        Fixture f = new Fixture(reasonCode);

        org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer pkixReviewer =
            new org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer();
        pkixReviewer.init(f.path, f.params);

        assertFalse("revoked path must not validate (pkix reviewer, reason " + reasonCode + ")",
            pkixReviewer.isValidCertPath());

        org.bouncycastle.x509.PKIXCertPathReviewer x509Reviewer =
            new org.bouncycastle.x509.PKIXCertPathReviewer();
        x509Reviewer.init(f.path, f.params);

        assertFalse("revoked path must not validate (x509 reviewer, reason " + reasonCode + ")",
            x509Reviewer.isValidCertPath());
    }

    private static class Fixture
    {
        final CertPath path;
        final PKIXParameters params;

        Fixture(BigInteger reasonCode)
            throws Exception
        {
            long now = System.currentTimeMillis();

            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
            kpGen.initialize(256);
            KeyPair rootKp = kpGen.generateKeyPair();
            KeyPair eeKp = kpGen.generateKeyPair();

            X500Name rootName = new X500Name("CN=Reason Test Root");

            ContentSigner rootSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC)
                .build(rootKp.getPrivate());

            JcaX509v3CertificateBuilder rootBldr = new JcaX509v3CertificateBuilder(rootName,
                BigInteger.valueOf(1), new Date(now - 3600000L), new Date(now + 3600000L), rootName,
                rootKp.getPublic());
            rootBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rootBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC)
                .getCertificate(rootBldr.build(rootSigner));

            JcaX509v3CertificateBuilder eeBldr = new JcaX509v3CertificateBuilder(rootName,
                BigInteger.valueOf(2), new Date(now - 3600000L), new Date(now + 3600000L),
                new X500Name("CN=Reason Test EE"), eeKp.getPublic());
            eeBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            eeBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

            X509Certificate eeCert = new JcaX509CertificateConverter().setProvider(BC)
                .getCertificate(eeBldr.build(rootSigner));

            X509v2CRLBuilder crlBldr = new X509v2CRLBuilder(rootName, new Date(now));
            crlBldr.setNextUpdate(new Date(now + 3600000L));

            ExtensionsGenerator entryExtGen = new ExtensionsGenerator();
            entryExtGen.addExtension(Extension.reasonCode, false, new ASN1Enumerated(reasonCode));
            crlBldr.addCRLEntry(eeCert.getSerialNumber(), new Date(now - 60000L), entryExtGen.generate());

            X509CRLHolder crlHolder = crlBldr.build(rootSigner);
            X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
            List certList = new ArrayList();
            certList.add(eeCert);
            path = cf.generateCertPath(certList);

            Set anchors = new HashSet();
            anchors.add(new TrustAnchor(rootCert, null));

            params = new PKIXParameters(anchors);
            params.setRevocationEnabled(true);
            params.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Collections.singletonList(crl)), BC));
        }
    }
}
