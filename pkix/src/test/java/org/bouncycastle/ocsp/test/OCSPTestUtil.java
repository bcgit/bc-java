package org.bouncycastle.ocsp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class OCSPTestUtil
{
    
    public static SecureRandom     rand;
    public static KeyPairGenerator kpg, eckpg;
    public static KeyGenerator     desede128kg;
    public static KeyGenerator     desede192kg;
    public static KeyGenerator     rc240kg;
    public static KeyGenerator     rc264kg;
    public static KeyGenerator     rc2128kg;
    public static BigInteger       serialNumber;
    
    public static final boolean DEBUG = true;
    
    static
    {
        try
        {
            rand = new SecureRandom();

            kpg  = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024, rand);

            serialNumber = new BigInteger("1");

            eckpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            eckpg.initialize(192, rand);
        }
        catch(Exception ex)
        {
            throw new RuntimeException(ex.toString());
        }
    }
    
    public static KeyPair makeKeyPair()
    {
        return kpg.generateKeyPair();
    }

    public static KeyPair makeECKeyPair()
    {
        return eckpg.generateKeyPair();
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
            throws Exception
    {

        return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509Certificate makeECDSACertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
            throws Exception
    {

        return makeECDSACertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509Certificate makeCACertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
            throws Exception
    {

        return makeCertificate(_subKP, _subDN, _issKP, _issDN, true);
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN, boolean _ca)
            throws Exception
    {
        return makeCertificate(_subKP,_subDN, _issKP, _issDN, "MD5withRSA", _ca);
    }

    public static X509Certificate makeECDSACertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN, boolean _ca)
            throws Exception
    {
        return makeCertificate(_subKP,_subDN, _issKP, _issDN, "SHA1WithECDSA", _ca);
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN, String algorithm, boolean _ca)
            throws Exception
    {

        PublicKey _subPub = _subKP.getPublic();
        PrivateKey _issPriv = _issKP.getPrivate();
        PublicKey _issPub = _issKP.getPublic();

        X509V3CertificateGenerator _v3CertGen = new X509V3CertificateGenerator();

        _v3CertGen.reset();
        _v3CertGen.setSerialNumber(allocateSerialNumber());
        _v3CertGen.setIssuerDN(new X509Name(_issDN));
        _v3CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        _v3CertGen.setNotAfter(new Date(System.currentTimeMillis()
                + (1000L * 60 * 60 * 24 * 100)));
        _v3CertGen.setSubjectDN(new X509Name(_subDN));
        _v3CertGen.setPublicKey(_subPub);
        _v3CertGen.setSignatureAlgorithm(algorithm);

        _v3CertGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                createSubjectKeyId(_subPub));

        _v3CertGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                createAuthorityKeyId(_issPub));

        _v3CertGen.addExtension(X509Extensions.BasicConstraints, false,
                new BasicConstraints(_ca));

        X509Certificate _cert = _v3CertGen.generate(_issPriv);

        _cert.checkValidity(new Date());
        _cert.verify(_issPub);

        return _cert;
    }

    /*
     * 
     * INTERNAL METHODS
     * 
     */

    private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey _pubKey)
            throws IOException
    {

        ByteArrayInputStream _bais = new ByteArrayInputStream(_pubKey
                .getEncoded());
        SubjectPublicKeyInfo _info = new SubjectPublicKeyInfo(
                (ASN1Sequence)new ASN1InputStream(_bais).readObject());

        return new AuthorityKeyIdentifier(_info);
    }

    private static SubjectKeyIdentifier createSubjectKeyId(PublicKey _pubKey)
            throws IOException
    {

        ByteArrayInputStream _bais = new ByteArrayInputStream(_pubKey
                .getEncoded());
        SubjectPublicKeyInfo _info = new SubjectPublicKeyInfo(
                (ASN1Sequence)new ASN1InputStream(_bais).readObject());
        return new SubjectKeyIdentifier(_info);
    }

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.valueOf(1));
        return _tmp;
    }
}
