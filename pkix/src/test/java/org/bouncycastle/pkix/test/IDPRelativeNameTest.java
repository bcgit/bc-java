package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Per RFC 5280 sec. 4.2.1.13, IssuingDistributionPoint's
 * {@code nameRelativeToCRLIssuer} is a single RelativeDistinguishedName (a SET
 * of AttributeTypeAndValue) that, per sec. 5.2.5, is appended as one element
 * to the CRL issuer's RDNSequence to form the full distribution-point DN. This
 * test exercises the spec-compliant case where that single RDN is multi-valued
 * (O=Bouncy+OU=Test) so the expansion in RFC3280CertPathUtilities goes through
 * the SET-as-one-RDN path — locking in behaviour the schema mandates and that
 * github #1241 questioned (issue closed as not-a-bug; the schema does not
 * permit a sequence of RDNs here).
 */
public class IDPRelativeNameTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testMultiValuedRelativeNameRoundTrip()
        throws Exception
    {
        X500Name crlIssuerDn = new X500Name("CN=Root,O=BC");
        ASN1Set relativeRdn = (ASN1Set)new X500Name("O=Bouncy+OU=Test").getRDNs()[0].toASN1Primitive();
        X500Name expandedDn = new X500Name("CN=Root,O=BC,O=Bouncy+OU=Test");

        KeyPair caKp = generateRsaKp();
        X509Certificate caCert = TestUtil.makeTrustAnchor(caKp, "CN=Root,O=BC");
        X509Certificate eeCert = makeEe(caCert, caKp, expandedDn);

        X509CRL matchingCrl = makeCrlWithRelativeIdp(crlIssuerDn, caKp.getPrivate(), relativeRdn);
        runValidate(caCert, eeCert, matchingCrl);
    }

    public void testRelativeNameMismatchRejected()
        throws Exception
    {
        X500Name crlIssuerDn = new X500Name("CN=Root,O=BC");
        X500Name expandedDn = new X500Name("CN=Root,O=BC,O=Bouncy+OU=Test");

        KeyPair caKp = generateRsaKp();
        X509Certificate caCert = TestUtil.makeTrustAnchor(caKp, "CN=Root,O=BC");
        X509Certificate eeCert = makeEe(caCert, caKp, expandedDn);

        ASN1Set wrongRdn = (ASN1Set)new X500Name("O=Wrong+OU=Other").getRDNs()[0].toASN1Primitive();
        X509CRL mismatchingCrl = makeCrlWithRelativeIdp(crlIssuerDn, caKp.getPrivate(), wrongRdn);
        try
        {
            runValidate(caCert, eeCert, mismatchingCrl);
            fail("expected CertPathValidatorException; none thrown");
        }
        catch (CertPathValidatorException e)
        {
            String expectedPrefix = "No match for certificate CRL issuing distribution point name";
            Throwable cause = e;
            while (cause != null)
            {
                String msg = cause.getMessage();
                if (msg != null && msg.startsWith(expectedPrefix))
                {
                    return;
                }
                cause = cause.getCause();
            }
            fail("unexpected exception message: " + e.getMessage());
        }
    }

    private static KeyPair generateRsaKp()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    private static X509Certificate makeEe(X509Certificate ca, KeyPair caKp, X500Name expandedDn)
        throws Exception
    {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            ca,
            BigInteger.valueOf(2),
            new Date(now - 60000L),
            new Date(now + 365L * 24 * 60 * 60 * 1000),
            new X500Principal("CN=EE"),
            caKp.getPublic());
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

        DistributionPointName dpName = new DistributionPointName(
            new GeneralNames(new GeneralName(expandedDn)));
        DistributionPoint dp = new DistributionPoint(dpName, null, null);
        builder.addExtension(Extension.cRLDistributionPoints, false,
            new CRLDistPoint(new DistributionPoint[] { dp }));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static X509CRL makeCrlWithRelativeIdp(X500Name issuerDn, PrivateKey issuerKey, ASN1Set relativeRdn)
        throws Exception
    {
        Date now = new Date();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuerDn, now);
        builder.setNextUpdate(new Date(now.getTime() + 60L * 60 * 1000));

        DistributionPointName dpName = new DistributionPointName(
            DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER, relativeRdn);
        IssuingDistributionPoint idp = new IssuingDistributionPoint(dpName, false, false);
        builder.addExtension(Extension.issuingDistributionPoint, true, idp);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);
        return new JcaX509CRLConverter().setProvider("BC").getCRL(builder.build(signer));
    }

    private void runValidate(X509Certificate ca, X509Certificate ee, X509CRL crl)
        throws Exception
    {
        List store = new ArrayList();
        store.add(ca);
        store.add(ee);
        store.add(crl);
        CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(store), "BC");

        List chain = new ArrayList();
        chain.add(ee);
        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(chain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(ca, null));

        PKIXParameters params = new PKIXParameters(trust);
        params.addCertStore(certStore);
        params.setRevocationEnabled(true);
        params.setDate(new Date());

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        cpv.validate(cp, params);
    }
}
