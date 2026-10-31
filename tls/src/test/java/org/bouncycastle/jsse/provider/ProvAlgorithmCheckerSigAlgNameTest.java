package org.bouncycastle.jsse.provider;

import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import junit.framework.TestCase;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * The certificate signature algorithm name checked against the TLS algorithm constraints must come
 * from the OID, not from X509Certificate.getSigAlgName(), whose spelling depends on the certificate
 * implementation and the registered providers - Android 4.1's bundled BC 1.46, registered as "BC",
 * names sha256WithRSAEncryption "SHA256WithRSAEncryption", which matches no supported signature
 * scheme (github #2506).
 */
public class ProvAlgorithmCheckerSigAlgNameTest
    extends TestCase
{
    private static final String FOREIGN_NAME = "SHA256WithRSAEncryption";

    public void testFixedNamesIgnoreCertificateSpelling()
    {
        checkName(PKCSObjectIdentifiers.md5WithRSAEncryption.getId(), "MD5withRSA");
        checkName(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1withRSA");
        checkName(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224withRSA");
        checkName(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256withRSA");
        checkName(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384withRSA");
        checkName(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512withRSA");

        checkName(X9ObjectIdentifiers.ecdsa_with_SHA1.getId(), "SHA1withECDSA");
        checkName(X9ObjectIdentifiers.ecdsa_with_SHA224.getId(), "SHA224withECDSA");
        checkName(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), "SHA256withECDSA");
        checkName(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), "SHA384withECDSA");
        checkName(X9ObjectIdentifiers.ecdsa_with_SHA512.getId(), "SHA512withECDSA");

        checkName(NISTObjectIdentifiers.dsa_with_sha224.getId(), "SHA224withDSA");
        checkName(NISTObjectIdentifiers.dsa_with_sha256.getId(), "SHA256withDSA");

        checkName(GMObjectIdentifiers.sm2sign_with_sm3.getId(), "SM3withSM2");
    }

    public void testUnknownOidFallsBackToCertificate()
    {
        X509Certificate cert = new NamedCertificate("1.2.3.4.5", "SomeAlgorithm");

        assertEquals("SomeAlgorithm", ProvAlgorithmChecker.getSigAlgName(cert, null));
    }

    private static void checkName(String oid, String expected)
    {
        X509Certificate cert = new NamedCertificate(oid, FOREIGN_NAME);

        assertEquals(oid, expected, ProvAlgorithmChecker.getSigAlgName(cert, null));
        assertEquals(oid, expected, ProvAlgorithmChecker.getSigAlgName(cert, cert));
    }

    /**
     * Only the signature algorithm accessors are meaningful.
     */
    private static class NamedCertificate
        extends X509Certificate
    {
        private final String sigAlgOID;
        private final String sigAlgName;

        NamedCertificate(String sigAlgOID, String sigAlgName)
        {
            this.sigAlgOID = sigAlgOID;
            this.sigAlgName = sigAlgName;
        }

        public String getSigAlgName()
        {
            return sigAlgName;
        }

        public String getSigAlgOID()
        {
            return sigAlgOID;
        }

        public byte[] getSigAlgParams()
        {
            return null;
        }

        public void checkValidity()
        {
        }

        public void checkValidity(Date date)
        {
        }

        public int getVersion()
        {
            return 3;
        }

        public BigInteger getSerialNumber()
        {
            return BigInteger.ONE;
        }

        public Principal getIssuerDN()
        {
            return null;
        }

        public Principal getSubjectDN()
        {
            return null;
        }

        public Date getNotBefore()
        {
            return null;
        }

        public Date getNotAfter()
        {
            return null;
        }

        public byte[] getTBSCertificate()
        {
            return new byte[0];
        }

        public byte[] getSignature()
        {
            return new byte[0];
        }

        public boolean[] getIssuerUniqueID()
        {
            return null;
        }

        public boolean[] getSubjectUniqueID()
        {
            return null;
        }

        public boolean[] getKeyUsage()
        {
            return null;
        }

        public int getBasicConstraints()
        {
            return -1;
        }

        public byte[] getEncoded()
        {
            return new byte[0];
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
            return "NamedCertificate(" + sigAlgOID + ", " + sigAlgName + ")";
        }

        public PublicKey getPublicKey()
        {
            return null;
        }

        public boolean hasUnsupportedCriticalExtension()
        {
            return false;
        }

        public Set<String> getCriticalExtensionOIDs()
        {
            return null;
        }

        public Set<String> getNonCriticalExtensionOIDs()
        {
            return null;
        }

        public byte[] getExtensionValue(String oid)
        {
            return null;
        }
    }
}
