package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 * Test Utils
 */
class TestUtils
{
    private static AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());
    private static Map algIds = new HashMap();

    static
    {
        algIds.put("GOST3411withGOST3410", new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94));
        algIds.put("SHA1withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));
        algIds.put("SHA256withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
        algIds.put("SHA1withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1));
        algIds.put("SHA256withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256));
        algIds.put("Ed448", new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448));
    }

    public static X509Certificate createSelfSignedCert(String dn, String sigName, KeyPair keyPair)
        throws Exception
    {
        return createSelfSignedCert(new X500Name(dn), sigName, keyPair);
    }

    public static X509Certificate createSelfSignedCert(X500Name dn, String sigName, KeyPair keyPair)
        throws Exception
    {
        V1TBSCertificateGenerator certGen = new V1TBSCertificateGenerator();

        long time = System.currentTimeMillis();

        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(dn);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 1000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(keyPair.getPrivate());

        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    public static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, String dn, String sigName, Extensions extensions, PublicKey pubKey)
        throws Exception
    {
        return createCert(signerName, signerKey, new X500Name(dn), sigName, extensions, pubKey);
    }

    public static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, X500Name dn, String sigName, Extensions extensions, PublicKey pubKey)
        throws Exception
    {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        long time = System.currentTimeMillis();

        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(signerName);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 1000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
        certGen.setExtensions(extensions);

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, "BC");
        sig.initSign(signerKey);
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static X509Certificate generateRootCert(KeyPair pair)
        throws Exception
    {
        return createSelfSignedCert("CN=Test CA Certificate", "SHA256withRSA", pair);
    }

    public static X509Certificate generateRootCert(KeyPair pair, X500Name dn)
        throws Exception
    {
        return createSelfSignedCert(dn, "SHA256withRSA", pair);
    }

    public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateIntermediateCert(
            intKey, new X500Name("CN=Test Intermediate Certificate"), caKey, caCert);
    }

    public static X509Certificate generateIntermediateCert(PublicKey intKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        Certificate caCertLw = Certificate.getInstance(caCert.getEncoded());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(getDigest(caCertLw.getSubjectPublicKeyInfo()),
            new GeneralNames(new GeneralName(caCertLw.getIssuer())),
            caCertLw.getSerialNumber().getValue()));
        extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(intKey.getEncoded()))));
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return createCert(
            caCertLw.getSubject(),
            caKey, subject, "SHA256withRSA", extGen.generate(), intKey);
    }

    public static X509Certificate generateEndEntityCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCert(
            intKey, new X500Name("CN=Test End Certificate"), caKey, caCert);
    }

    public static X509Certificate generateEndEntityCert(PublicKey entityKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        Certificate caCertLw = Certificate.getInstance(caCert.getEncoded());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(getDigest(caCertLw.getSubjectPublicKeyInfo()),
            new GeneralNames(new GeneralName(caCertLw.getIssuer())),
            caCertLw.getSerialNumber().getValue()));
        extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(entityKey.getEncoded())));
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return createCert(
            caCertLw.getSubject(),
            caKey, subject, "SHA256withRSA", extGen.generate(), entityKey);
    }

    public static X509CRL createCRL(
        X509Certificate caCert,
        PrivateKey caKey,
        BigInteger serialNumber)
        throws Exception
    {
        X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
        Date now = new Date();
        BigInteger revokedSerialNumber = BigInteger.valueOf(2);

        crlGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(caCert));

        crlGen.setThisUpdate(now);
        crlGen.setNextUpdate(new Date(now.getTime() + 100000));
        crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        crlGen.addCRLEntry(serialNumber, now, CRLReason.privilegeWithdrawn);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

        return crlGen.generate(caKey, "BC");
    }

    public static X509Certificate createExceptionCertificate(boolean exceptionOnEncode)
    {
        return new ExceptionCertificate(exceptionOnEncode);
    }

    public static X500Name getCertIssuer(X509Certificate x509Certificate)
        throws CertificateEncodingException
    {
        return TBSCertificate.getInstance(x509Certificate.getTBSCertificate()).getIssuer();
    }

    public static X500Name getCertSubject(X509Certificate x509Certificate)
        throws CertificateEncodingException
    {
        return TBSCertificate.getInstance(x509Certificate.getTBSCertificate()).getSubject();
    }

    private static class ExceptionCertificate
        extends X509Certificate
    {
        private boolean _exceptionOnEncode;

        public ExceptionCertificate(boolean exceptionOnEncode)
        {
            _exceptionOnEncode = exceptionOnEncode;
        }

        public void checkValidity()
            throws CertificateExpiredException, CertificateNotYetValidException
        {
            throw new CertificateNotYetValidException();
        }

        public void checkValidity(Date date)
            throws CertificateExpiredException, CertificateNotYetValidException
        {
            throw new CertificateExpiredException();
        }

        public int getVersion()
        {
            return 0;
        }

        public BigInteger getSerialNumber()
        {
            return null;
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
            throws CertificateEncodingException
        {
            throw new CertificateEncodingException();
        }

        public byte[] getSignature()
        {
            return new byte[0];
        }

        public String getSigAlgName()
        {
            return null;
        }

        public String getSigAlgOID()
        {
            return null;
        }

        public byte[] getSigAlgParams()
        {
            return new byte[0];
        }

        public boolean[] getIssuerUniqueID()
        {
            return new boolean[0];
        }

        public boolean[] getSubjectUniqueID()
        {
            return new boolean[0];
        }

        public boolean[] getKeyUsage()
        {
            return new boolean[0];
        }

        public int getBasicConstraints()
        {
            return 0;
        }

        public byte[] getEncoded()
            throws CertificateEncodingException
        {
            if (_exceptionOnEncode)
            {
                throw new CertificateEncodingException();
            }

            return new byte[0];
        }

        public void verify(PublicKey key)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
        {
            throw new CertificateException();
        }

        public void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
        {
            throw new CertificateException();
        }

        public String toString()
        {
            return null;
        }

        public PublicKey getPublicKey()
        {
            return null;
        }

        public boolean hasUnsupportedCriticalExtension()
        {
            return false;
        }

        public Set getCriticalExtensionOIDs()
        {
            return null;
        }

        public Set getNonCriticalExtensionOIDs()
        {
            return null;
        }

        public byte[] getExtensionValue(String oid)
        {
            return new byte[0];
        }

    }

    private static byte[] getDigest(SubjectPublicKeyInfo spki)
    {
        return getDigest(spki.getPublicKeyData().getBytes());
    }

    private static byte[] getDigest(byte[] bytes)
    {
        Digest digest = new SHA1Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];

        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }

    private static class AtomicLong
    {
        private long value;

        public AtomicLong(long value)
        {
            this.value = value;
        }

        public synchronized long getAndIncrement()
        {
            return value++;
        }
    }
}
