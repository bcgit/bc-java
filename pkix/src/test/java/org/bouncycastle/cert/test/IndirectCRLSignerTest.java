package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * A root CA that delegates CRL signing to a separate certificate publishes an indirect CRL, and the
 * PKI carries two root generations whose CRL signers share a Subject DN. RFC 5280 sec. 6.3.3 (f)
 * requires the CRL issuer's certification path to be anchored at the same trust anchor as the
 * certificate under check, so a CRL signed by the other generation's signer cannot be used - but
 * the reason for that never reached the caller, who was told instead that no CRL had been found at
 * all (github #2427).
 */
public class IndirectCRLSignerTest
    extends SimpleTest
{
    private static final String SIG_ALG = "SHA256withRSA";

    private KeyPairGenerator kpg;
    private int serial = 1000;

    public String getName()
    {
        return "IndirectCRLSigner";
    }

    public void performTest()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024);

        singleGenerationValidates();
        rolledRootReportsTheRealFailure();
        excludedSignerIsNotUsed();
        maxPathLengthBoundsSignerPath();
        maxPathLengthUnboundedAdmitsLongSignerPath();
    }

    /**
     * The compatibility half: one root generation, so the delegated CRL signer necessarily chains
     * to the same trust anchor as the certificate being checked and the path validates.
     */
    private void singleGenerationValidates()
        throws Exception
    {
        if (validate(buildPki(1)) == null)
        {
            fail("CertPath build with a single root generation returned null");
        }
    }

    private void rolledRootReportsTheRealFailure()
        throws Exception
    {
        try
        {
            validate(buildPki(2));
            fail("CRL signed under a different trust anchor accepted");
        }
        catch (CertPathBuilderException e)
        {
            String chain = messageChain(e);

            isTrue("failure of the CRL signer's own path not reported: " + chain,
                chain.indexOf("CertPath for CRL signer failed to validate") >= 0);
            isTrue("distribution point failure not linked to the fallback: " + chain,
                chain.indexOf("The CRL distribution points of the certificate were tried first and failed") >= 0);
            // The certificate's own issuer is appended to the candidate signer set unconditionally,
            // and used to have the last word: it is a keyCertSign-only root, which is precisely why
            // CRL signing was delegated, so the caller was told the CRL issuer could not sign CRLs.
            isTrue("key usage of the certificate's issuer reported instead of the real failure: " + chain,
                chain.indexOf("Issuer certificate key usage extension does not permit CRL signing") < 0);
        }
    }

    /**
     * The caller's excluded certificates apply to the CRL signer's certification path too, so an
     * excluded signer cannot vouch for the CRL.
     */
    private void excludedSignerIsNotUsed()
        throws Exception
    {
        Pki pki = buildPki(1, 0);

        signerRejected("excluded CRL signer accepted", pki, 5, Collections.singleton(pki.signers.get(0)));
    }

    /**
     * The caller's maximum path length bounds the CRL signer's certification path, which here has two
     * intermediates between the signer and the root while the certificate under check has none.
     */
    private void maxPathLengthBoundsSignerPath()
        throws Exception
    {
        Pki pki = buildPki(1, 2);

        if (validate(pki, 2, null) == null)
        {
            fail("CRL signer path within the maximum path length rejected");
        }

        signerRejected("CRL signer path longer than the maximum path length accepted", pki, 1, null);
    }

    /**
     * A caller who lifts the path length limit gets it lifted for the CRL signer's path as well,
     * rather than having that path held to the builder default of 5.
     */
    private void maxPathLengthUnboundedAdmitsLongSignerPath()
        throws Exception
    {
        Pki pki = buildPki(1, 6);

        if (validate(pki, -1, null) == null)
        {
            fail("CRL signer path with an unlimited maximum path length rejected");
        }

        signerRejected("CRL signer path longer than the default maximum path length accepted", pki, 5, null);
    }

    private void signerRejected(String failMessage, Pki pki, int maxPathLength, Set excluded)
        throws Exception
    {
        try
        {
            validate(pki, maxPathLength, excluded);
            fail(failMessage);
        }
        catch (CertPathBuilderException e)
        {
            String chain = messageChain(e);

            isTrue("failure of the CRL signer's own path not reported: " + chain,
                chain.indexOf("CertPath for CRL signer failed to validate") >= 0);
        }
    }

    private static String messageChain(Throwable t)
    {
        StringBuffer sb = new StringBuffer();

        while (t != null)
        {
            sb.append(t.getMessage()).append(" | ");
            t = t.getCause();
        }

        return sb.toString();
    }

    private Object validate(Pki pki)
        throws Exception
    {
        return validate(pki, 5, null);
    }

    private Object validate(Pki pki, int maxPathLength, Set excluded)
        throws Exception
    {
        Set anchors = new HashSet();
        for (int i = 0; i != pki.roots.size(); i++)
        {
            anchors.add(new TrustAnchor((X509Certificate)pki.roots.get(i), null));
        }

        List storeContents = new ArrayList(pki.signers);
        storeContents.addAll(pki.intermediates);
        storeContents.add(pki.subCa);
        storeContents.add(pki.crl);

        X509CertSelector target = new X509CertSelector();
        target.setCertificate(pki.subCa);

        PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(storeContents), "BC"));
        params.setRevocationEnabled(true);
        params.setMaxPathLength(maxPathLength);

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
        if (excluded != null)
        {
            return builder.build(new PKIXExtendedBuilderParameters.Builder(params).addExcludedCerts(excluded).build());
        }

        return builder.build(params);
    }

    private static class Pki
    {
        final List roots = new ArrayList();
        final List signers = new ArrayList();
        final List intermediates = new ArrayList();
        X509Certificate subCa;
        X509CRL crl;
    }

    /**
     * Every generation issues a CRL signer carrying the same Subject DN, which is also the
     * cRLIssuer named by the distribution point of every certificate under any of the roots. The
     * certificate under check chains to the first generation while the single published CRL is
     * signed by the last generation's signer.
     */
    private Pki buildPki(int generations)
        throws Exception
    {
        return buildPki(generations, 0);
    }

    /**
     * As above, with each generation's CRL signer issued at the end of a chain of signerDepth
     * intermediate CAs under its root, all of them covered by the same indirect CRL.
     */
    private Pki buildPki(int generations, int signerDepth)
        throws Exception
    {
        Pki pki = new Pki();

        X500Name signerDn = new X500Name("CN=Test-Root.CRL-S, O=Test-PKI, C=DE");
        CRLDistPoint crlDp = new CRLDistPoint(new DistributionPoint[]{
            new DistributionPoint(null, null, new GeneralNames(new GeneralName(signerDn))) });

        List rootKeys = new ArrayList();
        List signerKeys = new ArrayList();

        for (int g = 1; g <= generations; g++)
        {
            KeyPair rootKey = kpg.generateKeyPair();
            X509Certificate root = selfSigned(rootKey,
                new X500Name("CN=Test-Root.CA, O=Test-PKI, C=DE, SERIALNUMBER=" + g));

            rootKeys.add(rootKey);
            pki.roots.add(root);

            KeyPair issuerKey = rootKey;
            X509Certificate issuer = root;
            for (int d = 1; d <= signerDepth; d++)
            {
                KeyPair caKey = kpg.generateKeyPair();
                issuer = subCa(caKey.getPublic(), new X500Name("CN=Test-Int" + d + ".CA, O=Test-PKI, C=DE, SERIALNUMBER=" + g),
                    issuerKey, issuer, crlDp);
                issuerKey = caKey;
                pki.intermediates.add(issuer);
            }

            KeyPair signerKey = kpg.generateKeyPair();
            // Self-referencing CRLDP: the signer's own path is validated with revocation enabled
            // before its key is trusted, so the signer needs a resolvable CRLDP of its own.
            pki.signers.add(crlSigner(signerKey.getPublic(), signerDn, issuerKey, issuer, crlDp));
            signerKeys.add(signerKey);
        }

        pki.subCa = subCa(kpg.generateKeyPair().getPublic(), new X500Name("CN=Test-Sub.CA, O=Test-PKI, C=DE"),
            (KeyPair)rootKeys.get(0), (X509Certificate)pki.roots.get(0), crlDp);

        int last = pki.signers.size() - 1;
        pki.crl = indirectCrl((KeyPair)signerKeys.get(last), (X509Certificate)pki.signers.get(last));

        return pki;
    }

    private X509Certificate selfSigned(KeyPair key, X500Name subject)
        throws Exception
    {
        X509v3CertificateBuilder b = builder(subject, subject, key.getPublic());

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        b.addExtension(Extension.subjectKeyIdentifier, false,
            new JcaX509ExtensionUtils().createSubjectKeyIdentifier(key.getPublic()));

        return sign(b, key.getPrivate());
    }

    private X509Certificate crlSigner(PublicKey pub, X500Name subject, KeyPair caKey, X509Certificate caCert,
        CRLDistPoint dp)
        throws Exception
    {
        X509v3CertificateBuilder b = builder(subjectOf(caCert), subject, pub);
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign));
        b.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(pub));
        b.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(caCert));
        b.addExtension(Extension.cRLDistributionPoints, false, dp);

        return sign(b, caKey.getPrivate());
    }

    private X509Certificate subCa(PublicKey pub, X500Name subject, KeyPair caKey, X509Certificate caCert,
        CRLDistPoint dp)
        throws Exception
    {
        X509v3CertificateBuilder b = builder(subjectOf(caCert), subject, pub);
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        b.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(pub));
        b.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(caCert));
        b.addExtension(Extension.cRLDistributionPoints, false, dp);

        return sign(b, caKey.getPrivate());
    }

    private X509CRL indirectCrl(KeyPair signerKey, X509Certificate signerCert)
        throws Exception
    {
        long now = System.currentTimeMillis();
        X509v2CRLBuilder b = new X509v2CRLBuilder(subjectOf(signerCert), new Date(now - 3600000L));

        b.setNextUpdate(new Date(now + 30L * 24 * 3600 * 1000));
        b.addExtension(Extension.issuingDistributionPoint, true,
            new IssuingDistributionPoint(null, false, false, null, true, false));
        b.addExtension(Extension.authorityKeyIdentifier, false,
            new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signerCert));

        ContentSigner cs = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(signerKey.getPrivate());

        return new JcaX509CRLConverter().setProvider("BC").getCRL(b.build(cs));
    }

    private static X500Name subjectOf(X509Certificate cert)
    {
        return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    }

    private X509v3CertificateBuilder builder(X500Name issuer, X500Name subject, PublicKey pub)
    {
        long now = System.currentTimeMillis();

        return new X509v3CertificateBuilder(issuer, BigInteger.valueOf(serial++), new Date(now - 24L * 3600 * 1000),
            new Date(now + 365L * 24 * 3600 * 1000), subject, SubjectPublicKeyInfo.getInstance(pub.getEncoded()));
    }

    private X509Certificate sign(X509v3CertificateBuilder b, java.security.PrivateKey key)
        throws Exception
    {
        ContentSigner cs = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(key);
        X509CertificateHolder h = b.build(cs);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(h);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new IndirectCRLSignerTest());
    }
}
