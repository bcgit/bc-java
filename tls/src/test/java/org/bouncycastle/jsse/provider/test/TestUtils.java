package org.bouncycastle.jsse.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
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
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * Test Utils
 */
class TestUtils
{
    static final SecureRandom RANDOM = new SecureRandom();

    private static AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());
    private static Map<String, AlgorithmIdentifier> algIDs = createAlgIds();

    private static Map<String, AlgorithmIdentifier> createAlgIds()
    {
        Map<String, AlgorithmIdentifier> algIDs = new HashMap<String, AlgorithmIdentifier>();

        algIDs.put("SHA1withDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa_with_sha1));
        algIDs.put("SHA224withDSA", new AlgorithmIdentifier(NISTObjectIdentifiers.dsa_with_sha224));
        algIDs.put("SHA256withDSA", new AlgorithmIdentifier(NISTObjectIdentifiers.dsa_with_sha256));
        algIDs.put("SHA1withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));
        algIDs.put("SHA224withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha224WithRSAEncryption, DERNull.INSTANCE));
        algIDs.put("SHA256withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
        algIDs.put("SHA256withRSAandMGF1",
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                new RSASSAPSSparams(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                    new ASN1Integer(32), new ASN1Integer(1))));
        algIDs.put("SHA1withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1));
        algIDs.put("SHA224withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA224));
        algIDs.put("SHA256withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256));
        algIDs.put("Ed25519", new AlgorithmIdentifier(TestOIDs.id_Ed25519));
        algIDs.put("Ed448", new AlgorithmIdentifier(TestOIDs.id_Ed448));

        return Collections.unmodifiableMap(algIDs);
    }

    private static AlgorithmIdentifier getAlgID(String sigAlgName)
    {
        AlgorithmIdentifier algID = algIDs.get(sigAlgName);
        if (null == algID)
        {
            throw new IllegalArgumentException();
        }
        return algID;
    }

    public static X509Certificate createSelfSignedCert(String dn, String sigName, KeyPair keyPair)
        throws Exception
    {
        return createSelfSignedCert(new X500Name(dn), sigName, keyPair);
    }

    public static X509Certificate createSelfSignedCert(X500Name dn, String sigName, KeyPair keyPair)
        throws Exception
    {
        AlgorithmIdentifier sigAlgID = getAlgID(sigName);

        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        long time = System.currentTimeMillis();

        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(dn);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 1000)));
        certGen.setSignature(sigAlgID);
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        // some cert path analysers will reject a V3 certificate as a CA if it doesn't have basic constraints set.
        certGen.setExtensions(new Extensions(
            new Extension(Extension.basicConstraints, false, new BasicConstraints(true).getEncoded())));

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, ProviderUtils.PROVIDER_NAME_BC);
        sig.initSign(keyPair.getPrivate());
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(sigAlgID);
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", ProviderUtils.PROVIDER_NAME_BC)
            .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
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
        certGen.setSignature(getAlgID(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
        certGen.setExtensions(extensions);

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, ProviderUtils.PROVIDER_NAME_BC);
        sig.initSign(signerKey);
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(getAlgID(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", ProviderUtils.PROVIDER_NAME_BC)
            .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    /**
     * Create a random 1024 bit DSA key pair
     */
    public static KeyPair generateDSAKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", ProviderUtils.PROVIDER_NAME_BC);

        kpGen.initialize(1024, RANDOM);

        return kpGen.generateKeyPair();
    }

    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", ProviderUtils.PROVIDER_NAME_BC);

        kpGen.initialize(1024, RANDOM);

        return kpGen.generateKeyPair();
    }

    /**
     * Create a random 1024 bit RSASSA-PSS key pair
     */
    public static KeyPair generatePSSKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSASSA-PSS", ProviderUtils.PROVIDER_NAME_BC);

        kpGen.initialize(1024, RANDOM);

        return kpGen.generateKeyPair();
    }

    public static KeyPair generateECKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", ProviderUtils.PROVIDER_NAME_BC);

        kpGen.initialize(256, RANDOM);

        return kpGen.generateKeyPair();
    }

    public static KeyPair generateEd25519KeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Ed25519", ProviderUtils.PROVIDER_NAME_BC);

        kpGen.initialize(255, RANDOM);

        return kpGen.generateKeyPair();
    }

    public static KeyPair generateEd448KeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Ed448", ProviderUtils.PROVIDER_NAME_BC);

        kpGen.initialize(448, RANDOM);

        return kpGen.generateKeyPair();
    }

    public static X509Certificate generateRootCert(KeyPair pair)
        throws Exception
    {
        String alg = pair.getPublic().getAlgorithm();
        if (alg.equals("DSA"))
        {
            return createSelfSignedCert("CN=Test CA Certificate", "SHA256withDSA", pair);
        }
        else if (alg.equals("RSA"))
        {
            return createSelfSignedCert("CN=Test CA Certificate", "SHA256withRSA", pair);
        }
        else if (alg.equals("RSASSA-PSS"))
        {
            return createSelfSignedCert("CN=Test CA Certificate", "SHA256withRSAandMGF1", pair);
        }
        else if (alg.equals("EC"))
        {
            return createSelfSignedCert("CN=Test CA Certificate", "SHA256withECDSA", pair);
        }
        else if (alg.equals("Ed25519"))
        {
            return createSelfSignedCert("CN=Test CA Certificate", "Ed25519", pair);
        }
        else if (alg.equals("Ed448"))
        {
            return createSelfSignedCert("CN=Test CA Certificate", "Ed448", pair);
        }
        else
        {
            throw new IllegalArgumentException();
        }
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

        if (intKey.getAlgorithm().equals("RSA"))
        {
            return createCert(
                caCertLw.getSubject(),
                caKey, subject, "SHA256withRSA", extGen.generate(), intKey);
        }
        else
        {
            return createCert(
                caCertLw.getSubject(),
                caKey, subject, "SHA256withECDSA", extGen.generate(), intKey);
        }
    }

    public static X509Certificate generateEndEntityCertAgree(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCertAgree(intKey, new X500Name("CN=Test End Certificate"), caKey, caCert);
    }

    public static X509Certificate generateEndEntityCertEnc(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCertEnc(intKey, new X500Name("CN=Test End Certificate"), caKey, caCert);
    }

    public static X509Certificate generateEndEntityCertSign(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCertSign(intKey, new X500Name("CN=Test End Certificate"), caKey, caCert);
    }

    public static X509Certificate generateEndEntityCertAgree(PublicKey entityKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCert(entityKey, subject, KeyUsage.keyAgreement, caKey, caCert);
    }

    public static X509Certificate generateEndEntityCertEnc(PublicKey entityKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCert(entityKey, subject, KeyUsage.keyEncipherment, caKey, caCert);
    }

    public static X509Certificate generateEndEntityCertSign(PublicKey entityKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCert(entityKey, subject, KeyUsage.digitalSignature, caKey, caCert);
    }

    public static X509Certificate generateEndEntityCert(PublicKey entityKey, X500Name subject, int keyUsage, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        Certificate caCertLw = Certificate.getInstance(caCert.getEncoded());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(getDigest(caCertLw.getSubjectPublicKeyInfo()),
            new GeneralNames(new GeneralName(caCertLw.getIssuer())),
            caCertLw.getSerialNumber().getValue()));
        extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(entityKey.getEncoded())));
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));

        if (entityKey.getAlgorithm().equals("RSA"))
        {
            return createCert(caCertLw.getSubject(), caKey, subject, "SHA256withRSA", extGen.generate(), entityKey);
        }
        else if (entityKey.getAlgorithm().equals("EC"))
        {
            return createCert(caCertLw.getSubject(), caKey, subject, "SHA256withECDSA", extGen.generate(), entityKey);
        }
        else if (entityKey.getAlgorithm().equals("Ed25519"))
        {
            return createCert(caCertLw.getSubject(), caKey, subject, "Ed25519", extGen.generate(), entityKey);
        }
        else if (entityKey.getAlgorithm().equals("Ed448"))
        {
            return createCert(caCertLw.getSubject(), caKey, subject, "Ed448", extGen.generate(), entityKey);
        }
        else
        {
            throw new IllegalArgumentException();
        }
    }

    public static byte[] getChannelBinding(SSLSocket s, String channelBinding)
    {
        if (s instanceof BCSSLSocket)
        {
            BCSSLConnection connection = ((BCSSLSocket)s).getConnection();
            if (connection != null)
            {
                return connection.getChannelBinding(channelBinding);
            }
        }
        return null;
    }

    public static X509Certificate createExceptionCertificate(boolean exceptionOnEncode)
    {
        return new ExceptionCertificate(exceptionOnEncode);
    }

    static KeyManagerFactory getSunX509KeyManagerFactory()
        throws NoSuchAlgorithmException
    {
        if (Security.getProvider("IBMJSSE2") != null)
        {
            return KeyManagerFactory.getInstance("IBMX509");
        }
        else
        {
            return KeyManagerFactory.getInstance("SunX509");
        }
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
            return new byte[0];
        }

    }

    private static byte[] getDigest(SubjectPublicKeyInfo spki)
        throws IOException, NoSuchAlgorithmException
    {
        return getDigest(spki.getPublicKeyData().getBytes());
    }

    private static byte[] getDigest(byte[] bytes)
        throws IOException, NoSuchAlgorithmException
    {
        MessageDigest calc = MessageDigest.getInstance("SHA1");

        return calc.digest(bytes);
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

    // needed for FIPS.
    static boolean hasClass(String name)
    {
        try
        {
            Class<?> clazz = TestUtils.class.getClassLoader().loadClass(name);

            return clazz != null;
        }
        catch (Exception e)
        {
            return false;
        }
    }
}
