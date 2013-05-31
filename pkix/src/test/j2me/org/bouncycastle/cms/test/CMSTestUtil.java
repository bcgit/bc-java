package org.bouncycastle.cms.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

public class CMSTestUtil
{

    public static SecureRandom rand;
    public static RSAKeyPairGenerator kpg;

    public static BigInteger serialNumber;

    public static final boolean DEBUG = true;

    private static byte[] attrCert = Base64.decode(
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
            rand = new SecureRandom();

            kpg = new RSAKeyPairGenerator();
            kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 1024, 25));

            serialNumber = new BigInteger("1");
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.toString());
        }
    }

    public static String dumpBase64(
        byte[] data)
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

    public static X509AttributeCertificateHolder getAttributeCertificate()
        throws Exception
    {
        return new X509AttributeCertificateHolder(CMSTestUtil.attrCert);
    }

    public static AsymmetricCipherKeyPair makeKeyPair()
    {
        return kpg.generateKeyPair();
    }

    public static X509CertificateHolder makeCertificate(AsymmetricCipherKeyPair _subKP,
                                                        String _subDN, AsymmetricCipherKeyPair _issKP, String _issDN)
        throws IOException, OperatorCreationException
    {

        return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509CertificateHolder makeCACertificate(AsymmetricCipherKeyPair _subKP,
                                                          String _subDN, AsymmetricCipherKeyPair _issKP, String _issDN)
        throws IOException, OperatorCreationException
    {

        return makeCertificate(_subKP, _subDN, _issKP, _issDN, true);
    }

    public static X509CertificateHolder makeV1Certificate(AsymmetricCipherKeyPair subKP, String _subDN, AsymmetricCipherKeyPair issKP, String _issDN)
        throws IOException, OperatorCreationException
    {
        RSAKeyParameters lwPubKey = (RSAKeyParameters)subKP.getPublic();

        X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(lwPubKey.getModulus(), lwPubKey.getExponent()))
        );

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build((AsymmetricKeyParameter)issKP.getPrivate());


        return v1CertGen.build(sigGen);
    }

    public static X509CertificateHolder makeCertificate(AsymmetricCipherKeyPair subKP, String _subDN, AsymmetricCipherKeyPair issKP, String _issDN, boolean _ca)
        throws IOException, OperatorCreationException
    {
        RSAKeyParameters lwPubKey = (RSAKeyParameters)subKP.getPublic();

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(lwPubKey.getModulus(), lwPubKey.getExponent()))
        );

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build((AsymmetricKeyParameter)issKP.getPrivate());

        v3CertGen.addExtension(
            X509Extension.basicConstraints,
            false,
            new BasicConstraints(_ca));

        return v3CertGen.build(sigGen);
    }

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return _tmp;
    }
}
