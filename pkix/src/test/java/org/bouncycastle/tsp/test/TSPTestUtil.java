package org.bouncycastle.tsp.test;

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
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

public class TSPTestUtil
{
    private static final String BC = "BC";

    public static SecureRandom rand = new SecureRandom();

    public static KeyPairGenerator kpg;

    public static KeyGenerator desede128kg;

    public static KeyGenerator desede192kg;

    public static KeyGenerator rc240kg;

    public static KeyGenerator rc264kg;

    public static KeyGenerator rc2128kg;

    public static BigInteger serialNumber = BigInteger.ONE;

    public static final boolean DEBUG = true;

    public static ASN1ObjectIdentifier EuroPKI_TSA_Test_Policy = new ASN1ObjectIdentifier(
        "1.3.6.1.4.1.5255.5.1");

    public static JcaX509ExtensionUtils extUtils;

    static
    {
        try
        {
            rand = new SecureRandom();

            kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024, rand);

            desede128kg = KeyGenerator.getInstance("DESEDE", "BC");
            desede128kg.init(112, rand);

            desede192kg = KeyGenerator.getInstance("DESEDE", "BC");
            desede192kg.init(168, rand);

            rc240kg = KeyGenerator.getInstance("RC2", "BC");
            rc240kg.init(40, rand);

            rc264kg = KeyGenerator.getInstance("RC2", "BC");
            rc264kg.init(64, rand);

            rc2128kg = KeyGenerator.getInstance("RC2", "BC");
            rc2128kg.init(128, rand);

            serialNumber = new BigInteger("1");

            extUtils = new JcaX509ExtensionUtils();

        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.toString());
        }
    }

    public static String dumpBase64(byte[] data)
    {
        StringBuffer buf = new StringBuffer();

        data = Base64.encode(data);

        for (int i = 0; i < data.length; i += 64)
        {
            if (i + 64 < data.length)
            {
                buf.append(new String(data, i, 64));
            }
            else
            {
                buf.append(new String(data, i, data.length - i));
            }
            buf.append('\n');
        }

        return buf.toString();
    }

    public static KeyPair makeKeyPair()
    {
        return kpg.generateKeyPair();
    }

    public static SecretKey makeDesede128Key()
    {
        return desede128kg.generateKey();
    }

    public static SecretKey makeDesede192Key()
    {
        return desede192kg.generateKey();
    }

    public static SecretKey makeRC240Key()
    {
        return rc240kg.generateKey();
    }

    public static SecretKey makeRC264Key()
    {
        return rc264kg.generateKey();
    }

    public static SecretKey makeRC2128Key()
    {
        return rc2128kg.generateKey();
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
                                                  String _subDN, KeyPair _issKP, String _issDN)
        throws Exception
    {
        return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
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

        PublicKey _subPub = _subKP.getPublic();
        PrivateKey _issPriv = _issKP.getPrivate();
        PublicKey _issPub = _issKP.getPublic();

        X509v3CertificateBuilder _v3CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            _subPub)
            .addExtension(Extension.subjectKeyIdentifier, false,
                createSubjectKeyId(_subPub))
            .addExtension(Extension.authorityKeyIdentifier, false,
                createAuthorityKeyId(_issPub));

        if (_ca)
        {
            _v3CertGen.addExtension(Extension.basicConstraints, false,
                new BasicConstraints(_ca));
        }
        else
        {
            _v3CertGen.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        }

        X509CertificateHolder _cert = _v3CertGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_issPriv));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(_cert);
    }
    /*
     *
     *  INTERNAL METHODS
     *
     */


    private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey _pubKey)
        throws IOException
    {
        return extUtils.createAuthorityKeyIdentifier(_pubKey);
    }

    private static SubjectKeyIdentifier createSubjectKeyId(PublicKey _pubKey)
        throws IOException
    {
        return extUtils.createSubjectKeyIdentifier(_pubKey);
    }

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return _tmp;
    }
}
