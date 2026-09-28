package org.bouncycastle.cert.test;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.X509RevocationChecker;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.test.SimpleTest;

/**
 * An indirect CRL (RFC 5280 sec. 5.2.5) lists certificates from more than one issuer, and a serial
 * number is only unique within its issuer, so two of its entries may carry the same serial number
 * for different issuers, each applying to the issuer named by its own or a preceding entry's
 * certificateIssuer extension (sec. 5.3.3). An entry looked up by serial number alone is therefore
 * whichever of them comes first, and a certificate whose own entry followed another issuer's entry
 * with the same serial number was reported as not revoked.
 */
public class IndirectCRLSerialCollisionTest
    extends SimpleTest
{
    private static final String SIG_ALG = "SHA256withRSA";
    private static final BigInteger SHARED_SERIAL = BigInteger.valueOf(7);
    private static final X500Name OTHER_CA = new X500Name("CN=Other.CA, O=Test-PKI, C=DE");

    private KeyPair caKey;
    private X500Name caName;
    private X509Certificate caCert;

    public String getName()
    {
        return "IndirectCRLSerialCollision";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024);

        caKey = kpg.generateKeyPair();
        caName = new X500Name("CN=Test-Root.CA, O=Test-PKI, C=DE");
        caCert = selfSigned(caKey, caName);

        X509Certificate ee = certificate(kpg.generateKeyPair().getPublic(), caName,
            new X500Name("CN=Test-EE, O=Test-PKI, C=DE"), SHARED_SERIAL);
        // the same serial number under the other issuer: only that issuer's entry applies to it.
        X509Certificate other = certificate(kpg.generateKeyPair().getPublic(), OTHER_CA,
            new X500Name("CN=Other-EE, O=Test-PKI, C=DE"), SHARED_SERIAL);

        // the entry naming the CA follows the other issuer's entry for the same serial number.
        X509CRL otherFirst = indirectCrl(new X500Name[]{ OTHER_CA, caName });
        // the compatibility half: the entry naming the CA comes first.
        X509CRL caFirst = indirectCrl(new X500Name[]{ caName, OTHER_CA });
        // only the other issuer has revoked this serial number.
        X509CRL otherOnly = indirectCrl(new X500Name[]{ OTHER_CA });

        revokedBy(ee, caFirst, false);
        revokedBy(ee, otherFirst, false);
        validatesWith(ee, otherOnly, false);

        revokedBy(ee, caFirst, true);
        revokedBy(ee, otherFirst, true);
        validatesWith(ee, otherOnly, true);

        // the JDK's parse of the same CRLs, whose serial number lookup sees only the CRL issuer's entries -
        // before Java 7 the JDK has no indirect CRL support, and reports the critical issuingDistributionPoint as unsupported.
        if (!jdkCrl(otherFirst).hasUnsupportedCriticalExtension())
        {
            revokedBy(ee, jdkCrl(otherFirst), false);
            revokedBy(ee, jdkCrl(caFirst), false);
            validatesWith(ee, jdkCrl(otherOnly), false);
            revokedBy(ee, jdkCrl(otherFirst), true);
            validatesWith(ee, jdkCrl(otherOnly), true);
        }

        isRevoked(ee, other, caFirst, otherFirst, otherOnly);

        entryLookup(ee, other, otherFirst, otherOnly);
    }

    /**
     * CRL.isRevoked() stopped at the first entry carrying the serial number, and reported the
     * certificate as not revoked when that entry was another issuer's. The same checks run with the
     * certificates presented as a Certificate of type "X.509" that is not an X509Certificate, which
     * isRevoked() cast to one for its serial number, and against the legacy provider CRL class.
     */
    private void isRevoked(X509Certificate ee, X509Certificate other, X509CRL caFirst, X509CRL otherFirst, X509CRL otherOnly)
        throws Exception
    {
        Certificate opaqueEe = new OpaqueCertificate(ee);
        Certificate opaqueOther = new OpaqueCertificate(other);

        isRevoked("", ee, other, caFirst, otherFirst, otherOnly);
        isRevoked(" [not an X509Certificate]", opaqueEe, opaqueOther, caFirst, otherFirst, otherOnly);

        X509CRL legacyCaFirst = legacyCrl(caFirst);
        X509CRL legacyOtherFirst = legacyCrl(otherFirst);
        X509CRL legacyOtherOnly = legacyCrl(otherOnly);

        isRevoked(" [legacy CRL]", ee, other, legacyCaFirst, legacyOtherFirst, legacyOtherOnly);
        isRevoked(" [legacy CRL, not an X509Certificate]", opaqueEe, opaqueOther, legacyCaFirst, legacyOtherFirst, legacyOtherOnly);
    }

    private void isRevoked(String label, Certificate ee, Certificate other, X509CRL caFirst, X509CRL otherFirst, X509CRL otherOnly)
    {
        isTrue("revoked certificate not reported by isRevoked() (own entry first)" + label, caFirst.isRevoked(ee));
        isTrue("revoked certificate not reported by isRevoked() (other issuer's entry first)" + label, otherFirst.isRevoked(ee));
        isTrue("other issuer's revoked certificate not reported by isRevoked()" + label, otherFirst.isRevoked(other));
        isTrue("another issuer's entry reported by isRevoked()" + label, !otherOnly.isRevoked(ee));
    }

    private static X509CRL legacyCrl(X509CRL crl)
        throws Exception
    {
        return new org.bouncycastle.jce.provider.X509CRLObject(CertificateList.getInstance(crl.getEncoded()));
    }

    /**
     * A certificate of type "X.509" that is not a java.security.cert.X509Certificate, as another
     * provider's CertificateFactory may return.
     */
    private static class OpaqueCertificate
        extends Certificate
    {
        private final X509Certificate cert;

        OpaqueCertificate(X509Certificate cert)
        {
            super("X.509");

            this.cert = cert;
        }

        public byte[] getEncoded()
            throws CertificateEncodingException
        {
            return cert.getEncoded();
        }

        public void verify(PublicKey key)
        {
            throw new UnsupportedOperationException();
        }

        public void verify(PublicKey key, String sigProvider)
        {
            throw new UnsupportedOperationException();
        }

        public String toString()
        {
            return "OpaqueCertificate: " + cert.getSubjectX500Principal();
        }

        public PublicKey getPublicKey()
        {
            return cert.getPublicKey();
        }
    }

    private static X509CRL jdkCrl(X509CRL crl)
        throws Exception
    {
        return (X509CRL)CertificateFactory.getInstance("X.509", "SUN").generateCRL(new ByteArrayInputStream(crl.getEncoded()));
    }

    private void revokedBy(X509Certificate cert, X509CRL crl, boolean useChecker)
        throws Exception
    {
        try
        {
            validate(cert, crl, useChecker);
            fail("revoked certificate accepted (" + (useChecker ? "checker" : "validator") + ")");
        }
        catch (CertPathValidatorException e)
        {
            String chain = messageChain(e);

            isTrue("unexpected failure: " + chain, chain.indexOf("revocation") >= 0 || chain.indexOf("revoked") >= 0);
        }
    }

    private void validatesWith(X509Certificate cert, X509CRL crl, boolean useChecker)
        throws Exception
    {
        validate(cert, crl, useChecker);
    }

    /**
     * The BC provider's validator processes the CRL from a certificate store; the pkix
     * X509RevocationChecker takes it from a Store and runs as a PKIXCertPathChecker.
     */
    private void validate(X509Certificate cert, X509CRL crl, boolean useChecker)
        throws Exception
    {
        Set anchors = new HashSet();
        anchors.add(new TrustAnchor(caCert, null));

        PKIXParameters params = new PKIXParameters(anchors);

        if (useChecker)
        {
            List crls = new ArrayList();
            crls.add(crl);

            params.setRevocationEnabled(false);
            params.addCertPathChecker(new X509RevocationChecker.Builder(new TrustAnchor(caCert, null))
                .addCrls(new CollectionStore<CRL>(crls))
                .build());
        }
        else
        {
            List storeContents = new ArrayList();
            storeContents.add(crl);

            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(storeContents), "BC"));
            params.setRevocationEnabled(true);
        }

        CertPath path = CertificateFactory.getInstance("X.509", "BC").generateCertPath(Collections.singletonList(cert));

        CertPathValidator.getInstance("PKIX", "BC").validate(path, params);
    }

    /**
     * X509CRL.getRevokedCertificate(X509Certificate) is the JDK's lookup for indirect CRLs, keyed
     * by issuer and serial number; it has to find the entry naming the certificate's issuer, and
     * no other.
     */
    private void entryLookup(X509Certificate ee, X509Certificate other, X509CRL otherFirst, X509CRL otherOnly)
        throws Exception
    {
        // the two entries for the shared serial number encode identically and differ only in the
        // issuer they inherit, so the set of entries must keep them both.
        isTrue("entry for a second issuer lost from the set of entries", otherFirst.getRevokedCertificates().size() == 4);

        Method lookup;
        try
        {
            lookup = X509CRL.class.getMethod("getRevokedCertificate", new Class[]{ X509Certificate.class });
        }
        catch (NoSuchMethodException e)
        {
            return;     // X509CRL.getRevokedCertificate(X509Certificate) is only there from Java 7
        }

        X509CRLEntry entry = (X509CRLEntry)lookup.invoke(otherFirst, new Object[]{ ee });

        isTrue("no entry found for the certificate", entry != null);
        isTrue("another issuer's entry returned for the certificate", namesIssuer(entry, otherFirst, caName));

        entry = (X509CRLEntry)lookup.invoke(otherFirst, new Object[]{ other });

        isTrue("no entry found for the other issuer's certificate", entry != null);
        isTrue("wrong entry returned for the other issuer's certificate", namesIssuer(entry, otherFirst, OTHER_CA));

        isTrue("entry of another issuer returned for an unrevoked certificate", lookup.invoke(otherOnly, new Object[]{ ee }) == null);
    }

    private static boolean namesIssuer(X509CRLEntry entry, X509CRL crl, X500Name issuer)
    {
        X500Name entryIssuer = (entry.getCertificateIssuer() == null)
            ? X500Name.getInstance(crl.getIssuerX500Principal().getEncoded())
            : X500Name.getInstance(entry.getCertificateIssuer().getEncoded());

        return issuer.equals(entryIssuer);
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

    private X509Certificate selfSigned(KeyPair key, X500Name subject)
        throws Exception
    {
        X509v3CertificateBuilder b = builder(subject, subject, key.getPublic(), BigInteger.ONE);

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return sign(b, key.getPrivate());
    }

    private X509Certificate certificate(PublicKey pub, X500Name issuer, X500Name subject, BigInteger serial)
        throws Exception
    {
        X509v3CertificateBuilder b = builder(issuer, subject, pub, serial);

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        return sign(b, caKey.getPrivate());
    }

    /**
     * An indirect CRL issued by the CA, revoking SHARED_SERIAL once under each of the given
     * issuers, in that order. Each issuer's entries are introduced by one carrying the
     * certificateIssuer extension, which the entries after it inherit (RFC 5280 sec. 5.3.3).
     */
    private X509CRL indirectCrl(X500Name[] issuers)
        throws Exception
    {
        long now = System.currentTimeMillis();
        Date revocationDate = new Date(now - 3600000L);
        X509v2CRLBuilder b = new X509v2CRLBuilder(caName, revocationDate);

        b.setNextUpdate(new Date(now + 30L * 24 * 3600 * 1000));
        b.addExtension(Extension.issuingDistributionPoint, true,
            new IssuingDistributionPoint(null, false, false, null, true, false));

        for (int i = 0; i != issuers.length; i++)
        {
            ExtensionsGenerator gen = new ExtensionsGenerator();

            gen.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(issuers[i])));

            b.addCRLEntry(BigInteger.valueOf(100 + i), revocationDate, gen.generate());
            b.addCRLEntry(SHARED_SERIAL, revocationDate, CRLReason.keyCompromise);
        }

        ContentSigner cs = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(caKey.getPrivate());

        return new JcaX509CRLConverter().setProvider("BC").getCRL(b.build(cs));
    }

    private X509v3CertificateBuilder builder(X500Name issuer, X500Name subject, PublicKey pub, BigInteger serial)
    {
        long now = System.currentTimeMillis();

        return new X509v3CertificateBuilder(issuer, serial, new Date(now - 24L * 3600 * 1000),
            new Date(now + 365L * 24 * 3600 * 1000), subject, SubjectPublicKeyInfo.getInstance(pub.getEncoded()));
    }

    private X509Certificate sign(X509v3CertificateBuilder b, PrivateKey key)
        throws Exception
    {
        ContentSigner cs = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(key);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(cs));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new IndirectCRLSerialCollisionTest());
    }
}
