package org.bouncycastle.pkix.jcajce;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Tests for the package-private CRL revocation-entry evaluation. The entry with an
 * unsupported critical extension must be rejected (RFC 5280 sec. 6.3: an application that
 * cannot process a critical CRL entry extension must not use the CRL to determine status) -
 * the copy behind the PKIX revocation path used to accept such entries silently.
 */
public class RevocationUtilitiesTest
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

    public void testEntryWithUnsupportedCriticalExtensionRejected()
        throws Exception
    {
        Fixture f = new Fixture();

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(new ASN1ObjectIdentifier("1.2.3.4.5.6.7"), true, new DEROctetString(new byte[]{ 1 }));

        X509CRL crl = f.buildCRL(f.cert.getSerialNumber(), new Date(f.now.getTime() - 60000L), extGen);

        CertStatus certStatus = new CertStatus();
        try
        {
            RevocationUtilities.getCertStatus(f.now, crl, f.cert, certStatus);
            fail("entry with unsupported critical extension was accepted");
        }
        catch (AnnotatedException e)
        {
            assertEquals("CRL entry has unsupported critical extensions.", e.getMessage());
        }
    }

    public void testRevokedEntryReported()
        throws Exception
    {
        Fixture f = new Fixture();

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.keyCompromise));

        X509CRL crl = f.buildCRL(f.cert.getSerialNumber(), new Date(f.now.getTime() - 60000L), extGen);

        CertStatus certStatus = new CertStatus();
        RevocationUtilities.getCertStatus(f.now, crl, f.cert, certStatus);

        assertEquals(CRLReason.keyCompromise, certStatus.getCertStatus());
    }

    // RFC 5280 sec. 6.3.3 (i)/(j): a future-dated revocation only takes effect for the hard
    // reasons - keyCompromise does, certificateHold does not
    public void testFutureRevocationEffectiveness()
        throws Exception
    {
        Fixture f = new Fixture();
        Date future = new Date(f.now.getTime() + 3600000L);

        ExtensionsGenerator holdGen = new ExtensionsGenerator();
        holdGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.certificateHold));

        CertStatus certStatus = new CertStatus();
        RevocationUtilities.getCertStatus(f.now, f.buildCRL(f.cert.getSerialNumber(), future, holdGen), f.cert, certStatus);

        assertEquals(CertStatus.UNREVOKED, certStatus.getCertStatus());

        ExtensionsGenerator compromiseGen = new ExtensionsGenerator();
        compromiseGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.keyCompromise));

        certStatus = new CertStatus();
        RevocationUtilities.getCertStatus(f.now, f.buildCRL(f.cert.getSerialNumber(), future, compromiseGen), f.cert, certStatus);

        assertEquals(CRLReason.keyCompromise, certStatus.getCertStatus());
    }

    public void testUnlistedCertificateUnrevoked()
        throws Exception
    {
        Fixture f = new Fixture();

        X509CRL crl = f.buildCRL(f.cert.getSerialNumber().add(BigInteger.ONE), new Date(f.now.getTime() - 60000L), null);

        CertStatus certStatus = new CertStatus();
        RevocationUtilities.getCertStatus(f.now, crl, f.cert, certStatus);

        assertEquals(CertStatus.UNREVOKED, certStatus.getCertStatus());
    }

    private static class Fixture
    {
        final Date now = new Date();
        final KeyPair kp;
        final X500Name issuer = new X500Name("CN=Revocation Test CA");
        final X509Certificate cert;

        Fixture()
            throws Exception
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
            kpGen.initialize(256);
            kp = kpGen.generateKeyPair();

            X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(7),
                new Date(now.getTime() - 3600000L), new Date(now.getTime() + 3600000L),
                new X500Name("CN=Revocation Test EE"), kp.getPublic());

            cert = new JcaX509CertificateConverter().setProvider(BC)
                .getCertificate(certBldr.build(signer()));
        }

        ContentSigner signer()
            throws Exception
        {
            return new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(kp.getPrivate());
        }

        X509CRL buildCRL(BigInteger revokedSerial, Date revocationDate, ExtensionsGenerator entryExtGen)
            throws Exception
        {
            X509v2CRLBuilder crlBldr = new X509v2CRLBuilder(issuer, now);
            crlBldr.setNextUpdate(new Date(now.getTime() + 3600000L));

            if (entryExtGen != null)
            {
                crlBldr.addCRLEntry(revokedSerial, revocationDate, entryExtGen.generate());
            }
            else
            {
                crlBldr.addCRLEntry(revokedSerial, revocationDate, 0);
            }

            X509CRLHolder holder = crlBldr.build(signer());

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            return (X509CRL)fact.generateCRL(new java.io.ByteArrayInputStream(holder.getEncoded()));
        }
    }
}
