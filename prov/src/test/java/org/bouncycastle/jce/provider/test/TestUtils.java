package org.bouncycastle.jce.provider.test;

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
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 * Test Utils
 */
class TestUtils
{
    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair()
        throws Exception
    {
        KeyPairGenerator  kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    
        kpGen.initialize(1024, new SecureRandom());
    
        return kpGen.generateKeyPair();
    }
    
    public static X509Certificate generateRootCert(KeyPair pair)
        throws Exception
    {
        X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();
    
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal("CN=Test CA Certificate"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal("CN=Test CA Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
    
        return certGen.generate(pair.getPrivate(), "BC");
    }
    
    public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(caCert));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal("CN=Test Intermediate Certificate"));
        certGen.setPublicKey(intKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
    
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(intKey.getEncoded()))));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return certGen.generate(caKey, "BC");
    }
    
    public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(caCert));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal("CN=Test End Certificate"));
        certGen.setPublicKey(entityKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(entityKey.getEncoded()))));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        return certGen.generate(caKey, "BC");
    }
    
    public static X509CRL createCRL(
        X509Certificate caCert, 
        PrivateKey      caKey, 
        BigInteger      serialNumber)
        throws Exception
    {
        X509V2CRLGenerator   crlGen = new X509V2CRLGenerator();
        Date                 now = new Date();
        BigInteger           revokedSerialNumber = BigInteger.valueOf(2);
        
        crlGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(caCert));
        
        crlGen.setThisUpdate(now);
        crlGen.setNextUpdate(new Date(now.getTime() + 100000));
        crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        crlGen.addCRLEntry(serialNumber, now, CRLReason.privilegeWithdrawn);
        
        crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
        
        return crlGen.generate(caKey, "BC");
    }

    public static X509Certificate createExceptionCertificate(boolean exceptionOnEncode)
    {
        return new ExceptionCertificate(exceptionOnEncode);
    }

    private static class ExceptionCertificate
        extends X509Certificate
    {
        private boolean _exceptionOnEncode;

        public ExceptionCertificate(boolean exceptionOnEncode)
        {
            _exceptionOnEncode = exceptionOnEncode;
        }

        public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException
        {
            throw new CertificateNotYetValidException();
        }

        public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException
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

        public byte[] getTBSCertificate() throws CertificateEncodingException
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

        public byte[] getEncoded() throws CertificateEncodingException
        {
            if (_exceptionOnEncode)
            {
                throw new CertificateEncodingException();
            }
            
            return new byte[0];
        }

        public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
        {
            throw new CertificateException();
        }

        public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
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
        Digest digest = new SHA1Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];

        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }
}
