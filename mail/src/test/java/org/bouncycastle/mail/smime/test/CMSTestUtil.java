package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

public class CMSTestUtil
{
    public static SecureRandom     rand;
    public static KeyPairGenerator kpg;

    public static KeyPairGenerator gostKpg;
    public static KeyPairGenerator dsaKpg;
    public static KeyPairGenerator ecGostKpg;
    public static KeyPairGenerator ecDsaKpg;
    public static KeyGenerator     aes192kg;
    public static KeyGenerator     desede128kg;
    public static KeyGenerator     desede192kg;
    public static KeyGenerator     rc240kg;
    public static KeyGenerator     rc264kg;
    public static KeyGenerator     rc2128kg;
    public static KeyGenerator     aesKg;
    public static KeyGenerator     seedKg;
    public static KeyGenerator     camelliaKg;
    public static BigInteger       serialNumber;
    
    public static final boolean DEBUG = true;

    private static byte[]  attrCert = Base64.decode(
                "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
              + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
              + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
              + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
              + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
              + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
              + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
              + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
              + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
              + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
              + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
              + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
              + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
              + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
              + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
              + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
              + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
              + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
              + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
              + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
              + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
              + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
              + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
              + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
              + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
              + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
              + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
              + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
              + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
              + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
              + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
              + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
              + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
              + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
              + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
              + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
              + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
              + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
              + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");
    
    static
    {
        try
        {
            java.security.Security.addProvider(new BouncyCastleProvider());

            rand = new SecureRandom();

            kpg  = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024, rand);

            kpg  = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024, rand);

            gostKpg  = KeyPairGenerator.getInstance("GOST3410", "BC");
            GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId());
            
            gostKpg.initialize(gost3410P, new SecureRandom());
            
            dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
            DSAParameterSpec dsaSpec = new DSAParameterSpec(
                        new BigInteger("7434410770759874867539421675728577177024889699586189000788950934679315164676852047058354758883833299702695428196962057871264685291775577130504050839126673"),
                        new BigInteger("1138656671590261728308283492178581223478058193247"),
                        new BigInteger("4182906737723181805517018315469082619513954319976782448649747742951189003482834321192692620856488639629011570381138542789803819092529658402611668375788410"));

            dsaKpg.initialize(dsaSpec, new SecureRandom());

            ecGostKpg = KeyPairGenerator.getInstance("ECGOST3410", "BC");
            ecGostKpg.initialize(ECGOST3410NamedCurveTable.getParameterSpec("GostR3410-2001-CryptoPro-A"), new SecureRandom());

            ecDsaKpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            ecDsaKpg.initialize(239, new SecureRandom());

            aes192kg = KeyGenerator.getInstance("AES", "BC");
            aes192kg.init(192, rand);

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

            aesKg = KeyGenerator.getInstance("AES", "BC");

            seedKg = KeyGenerator.getInstance("SEED", "BC");

            camelliaKg = KeyGenerator.getInstance("Camellia", "BC");
            
            serialNumber = new BigInteger("1");
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.toString());
        }
    }
    
    public static String dumpBase64(
        byte[]  data)
    {
        StringBuffer    buf = new StringBuffer();
        
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

    public static X509AttributeCertificateHolder getAttributeCertificate()
        throws Exception
    {
        return  new X509AttributeCertificateHolder(CMSTestUtil.attrCert);
    }

    public static KeyPair makeKeyPair()
    {
        return kpg.generateKeyPair();
    }

    public static KeyPair makeGostKeyPair()
    {
        return gostKpg.generateKeyPair();
    }

    public static KeyPair makeDsaKeyPair()
    {
        return dsaKpg.generateKeyPair();
    }
    
    public static KeyPair makeEcDsaKeyPair()
    {
        return ecDsaKpg.generateKeyPair();
    }

    public static KeyPair makeEcGostKeyPair()
    {
        return ecGostKpg.generateKeyPair();
    }

    public static SecretKey makeDesede128Key()
    {
        return desede128kg.generateKey();
    }

    public static SecretKey makeAES192Key()
    {
        return aes192kg.generateKey();
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

    public static SecretKey makeSEEDKey()
    {
        return seedKg.generateKey();
    }

    public static SecretKey makeAESKey(int keySize)
    {
        aesKg.init(keySize);
        return aesKg.generateKey();
    }

    public static SecretKey makeCamelliaKey(int keySize)
    {
        camelliaKg.init(keySize);
        return camelliaKg.generateKey();
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509Certificate makeOaepCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        return makeOaepCertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509Certificate makeCACertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        return makeCertificate(_subKP, _subDN, _issKP, _issDN, true);
    }

    public static X509Certificate makeV1Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey  subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v1CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, boolean _ca)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey  subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();
        
        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(_ca));

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, AlgorithmIdentifier keyAlgID)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();
        SubjectPublicKeyInfo subPub = SubjectPublicKeyInfo.getInstance(subKP.getPublic().getEncoded());

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            new SubjectPublicKeyInfo(keyAlgID, subPub.parsePublicKey()));

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(false));

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public static X509Certificate makeOaepCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, boolean _ca)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        SubjectPublicKeyInfo  subPub  = SubjectPublicKeyInfo.getInstance(subKP.getPublic().getEncoded());
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, new RSAESOAEPparams()), subPub.parsePublicKey()));

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(_ca));

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    private static JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub)
    {
        JcaContentSignerBuilder contentSignerBuilder;
        if (issPub instanceof RSAPublicKey)
        {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1WithRSA");
        }
        else if (issPub.getAlgorithm().equals("DSA"))
        {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1withDSA");
        }
        else if (issPub.getAlgorithm().equals("ECDSA"))
        {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1withECDSA");
        }
        else if (issPub.getAlgorithm().equals("ECGOST3410"))
        {
            contentSignerBuilder = new JcaContentSignerBuilder("GOST3411withECGOST3410");
        }
        else
        {
            contentSignerBuilder = new JcaContentSignerBuilder("GOST3411WithGOST3410");
        }

        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);

        return contentSignerBuilder;
    }

    public static X509CRL makeCrl(KeyPair pair)
        throws Exception
    {
        Date                 now = new Date();
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlGen.build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(pair.getPrivate())));
    }

    /*  
     *  
     *  INTERNAL METHODS
     *  
     */ 

    private static final X509ExtensionUtils extUtils = new X509ExtensionUtils(new SHA1DigestCalculator());

    private static AuthorityKeyIdentifier createAuthorityKeyId(
        PublicKey _pubKey)
        throws IOException
    {
        return extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded()));
    }

    static SubjectKeyIdentifier createSubjectKeyId(
        SubjectPublicKeyInfo _pubKey)
        throws IOException
    {
        return extUtils.createSubjectKeyIdentifier(_pubKey);
    }

    static SubjectKeyIdentifier createSubjectKeyId(
        PublicKey _pubKey)
        throws IOException
    {
        return extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded()));
    }

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return _tmp;
    }
    
    public static byte[] streamToByteArray(
        InputStream in) 
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int ch;
        
        while ((ch = in.read()) >= 0)
        {
            bOut.write(ch);
        }
        
        return bOut.toByteArray();
    }
}
