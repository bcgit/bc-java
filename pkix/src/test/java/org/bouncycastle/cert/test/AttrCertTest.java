package org.bouncycastle.cert.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class AttrCertTest
    extends SimpleTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final RSAPrivateCrtKeySpec RSA_PRIVATE_KEY_SPEC = new RSAPrivateCrtKeySpec(
                new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
                new BigInteger("11", 16),
                new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
                new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
                new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
                new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
                new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
                new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    public static byte[]  attrCert = Base64.decode(
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

    byte[]  signCert = Base64.decode(
            "MIIGjTCCBXWgAwIBAgICAPswDQYJKoZIhvcNAQEEBQAwaTEdMBsGCSqGSIb3DQEJ"
          + "ARYOaXJtaGVscEB2dC5lZHUxLjAsBgNVBAMTJVZpcmdpbmlhIFRlY2ggQ2VydGlm"
          + "aWNhdGlvbiBBdXRob3JpdHkxCzAJBgNVBAoTAnZ0MQswCQYDVQQGEwJVUzAeFw0w"
          + "MzAxMzExMzUyMTRaFw0wNDAxMzExMzUyMTRaMIGDMRswGQYJKoZIhvcNAQkBFgxz"
          + "c2hhaEB2dC5lZHUxGzAZBgNVBAMTElN1bWl0IFNoYWggKHNzaGFoKTEbMBkGA1UE"
          + "CxMSVmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAxMQswCQYDVQQK"
          + "EwJ2dDELMAkGA1UEBhMCVVMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPDc"
          + "scgSKmsEp0VegFkuitD5j5PUkDuzLjlfaYONt2SN8WeqU4j2qtlCnsipa128cyKS"
          + "JzYe9duUdNxquh5BPIkMkHBw4jHoQA33tk0J/sydWdN74/AHPpPieK5GHwhU7GTG"
          + "rCCS1PJRxjXqse79ExAlul+gjQwHeldAC+d4A6oZAgMBAAGjggOmMIIDojAMBgNV"
          + "HRMBAf8EAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDAOBgNVHQ8BAf8EBAMCA/gwHQYD"
          + "VR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdDgQWBBRUIoWAzlXbzBYE"
          + "yVTjQFWyMMKo1jCBkwYDVR0jBIGLMIGIgBTgc3Fm+TGqKDhen+oKfbl+xVbj2KFt"
          + "pGswaTEdMBsGCSqGSIb3DQEJARYOaXJtaGVscEB2dC5lZHUxLjAsBgNVBAMTJVZp"
          + "cmdpbmlhIFRlY2ggQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxCzAJBgNVBAoTAnZ0"
          + "MQswCQYDVQQGEwJVU4IBADCBiwYJYIZIAYb4QgENBH4WfFZpcmdpbmlhIFRlY2gg"
          + "Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkgZGlnaXRhbCBjZXJ0aWZpY2F0ZXMgYXJl"
          + "IHN1YmplY3QgdG8gcG9saWNpZXMgbG9jYXRlZCBhdCBodHRwOi8vd3d3LnBraS52"
          + "dC5lZHUvY2EvY3BzLy4wFwYDVR0RBBAwDoEMc3NoYWhAdnQuZWR1MBkGA1UdEgQS"
          + "MBCBDmlybWhlbHBAdnQuZWR1MEMGCCsGAQUFBwEBBDcwNTAzBggrBgEFBQcwAoYn"
          + "aHR0cDovL2JveDE3Ny5jYy52dC5lZHUvY2EvaXNzdWVycy5odG1sMEQGA1UdHwQ9"
          + "MDswOaA3oDWGM2h0dHA6Ly9ib3gxNzcuY2MudnQuZWR1L2h0ZG9jcy1wdWJsaWMv"
          + "Y3JsL2NhY3JsLmNybDBUBgNVHSAETTBLMA0GCysGAQQBtGgFAQEBMDoGCysGAQQB"
          + "tGgFAQEBMCswKQYIKwYBBQUHAgEWHWh0dHA6Ly93d3cucGtpLnZ0LmVkdS9jYS9j"
          + "cHMvMD8GCWCGSAGG+EIBBAQyFjBodHRwOi8vYm94MTc3LmNjLnZ0LmVkdS9jZ2kt"
          + "cHVibGljL2NoZWNrX3Jldl9jYT8wPAYJYIZIAYb4QgEDBC8WLWh0dHA6Ly9ib3gx"
          + "NzcuY2MudnQuZWR1L2NnaS1wdWJsaWMvY2hlY2tfcmV2PzBLBglghkgBhvhCAQcE"
          + "PhY8aHR0cHM6Ly9ib3gxNzcuY2MudnQuZWR1L35PcGVuQ0E4LjAxMDYzMC9jZ2kt"
          + "cHVibGljL3JlbmV3YWw/MCwGCWCGSAGG+EIBCAQfFh1odHRwOi8vd3d3LnBraS52"
          + "dC5lZHUvY2EvY3BzLzANBgkqhkiG9w0BAQQFAAOCAQEAHJ2ls9yjpZVcu5DqiE67"
          + "r7BfkdMnm7IOj2v8cd4EAlPp6OPBmjwDMwvKRBb/P733kLBqFNWXWKTpT008R0KB"
          + "8kehbx4h0UPz9vp31zhGv169+5iReQUUQSIwTGNWGLzrT8kPdvxiSAvdAJxcbRBm"
          + "KzDic5I8PoGe48kSCkPpT1oNmnivmcu5j1SMvlx0IS2BkFMksr0OHiAW1elSnE/N"
          + "RuX2k73b3FucwVxB3NRo3vgoHPCTnh9r4qItAHdxFlF+pPtbw2oHESKRfMRfOIHz"
          + "CLQWSIa6Tvg4NIV3RRJ0sbCObesyg08lymalQMdkXwtRn5eGE00SHWwEUjSXP2gR"
          + "3g==");

    static byte[] certWithBaseCertificateID = Base64.decode(
            "MIIBqzCCARQCAQEwSKBGMD6kPDA6MQswCQYDVQQGEwJJVDEOMAwGA1UEChMFVU5JVE4xDDAKBgNV"
          + "BAsTA0RJVDENMAsGA1UEAxMEcm9vdAIEAVMVjqB6MHikdjB0MQswCQYDVQQGEwJBVTEoMCYGA1UE"
          + "ChMfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTEjMCEGA1UECxMaQm91bmN5IFByaW1h"
          + "cnkgQ2VydGlmaWNhdGUxFjAUBgNVBAMTDUJvdW5jeSBDYXN0bGUwDQYJKoZIhvcNAQEFBQACBQKW"
          + "RhnHMCIYDzIwMDUxMjEyMTIwMDQyWhgPMjAwNTEyMTkxMjAxMzJaMA8wDQYDVRhIMQaBBGVWSVAw"
          + "DQYJKoZIhvcNAQEFBQADgYEAUAVin9StDaA+InxtXq/av6rUQLI9p1X6louBcj4kYJnxRvTrHpsr"
          + "N3+i9Uq/uk5lRdAqmPFvcmSbuE3TRAsjrXON5uFiBBKZ1AouLqcr8nHbwcdwjJ9TyUNO9I4hfpSH"
          + "UHHXMtBKgp4MOkhhX8xTGyWg3hp23d3GaUeg/IYlXBI=");
    
    byte[] holderCertWithBaseCertificateID = Base64.decode(
            "MIIBwDCCASmgAwIBAgIEAVMVjjANBgkqhkiG9w0BAQUFADA6MQswCQYDVQQGEwJJVDEOMAwGA1UE"
          + "ChMFVU5JVE4xDDAKBgNVBAsTA0RJVDENMAsGA1UEAxMEcm9vdDAeFw0wNTExMTExMjAxMzJaFw0w"
          + "NjA2MTYxMjAxMzJaMD4xCzAJBgNVBAYTAklUMQ4wDAYDVQQKEwVVTklUTjEMMAoGA1UECxMDRElU"
          + "MREwDwYDVQQDEwhMdWNhQm9yejBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr"
          + "5YtqKmKXmEGb4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERoxUw"
          + "EzARBglghkgBhvhCAQEEBAMCBDAwDQYJKoZIhvcNAQEFBQADgYEAsX50VPQQCWmHvPq9y9DeCpmS"
          + "4szcpFAhpZyn6gYRwY9CRZVtmZKH8713XhkGDWcIEMcG0u3oTz3tdKgPU5uyIPrDEWr6w8ClUj4x"
          + "5aVz5c2223+dVY7KES//JSB2bE/KCIchN3kAioQ4K8O3e0OL6oDVjsqKGw5bfahgKuSIk/Q=");

    
    public String getName()
    {
        return "AttrCertTest";
    }

    private void testCertWithBaseCertificateID()
        throws Exception
    {
        X509AttributeCertificateHolder attrCert = new X509AttributeCertificateHolder(certWithBaseCertificateID);
        CertificateFactory       fact = CertificateFactory.getInstance("X.509", "BC");   
        X509Certificate          cert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(holderCertWithBaseCertificateID));
        
        AttributeCertificateHolder holder = attrCert.getHolder();
        
        if (holder.getEntityNames() != null)
        {
            fail("entity names set when none expected");
        }
        
        if (!holder.getSerialNumber().equals(cert.getSerialNumber()))
        {
            fail("holder serial number doesn't match");
        }

        if (!holder.getIssuer()[0].equals(X500Name.getInstance(cert.getIssuerX500Principal().getEncoded())))
        {
            fail("holder issuer doesn't match");
        }
        
        if (!holder.match(new JcaX509CertificateHolder(cert)))
        {
            fail("holder not matching holder certificate");
        }

        if (!holder.equals(holder.clone()))
        {
            fail("holder clone test failed");
        }

        if (!attrCert.getIssuer().equals(attrCert.getIssuer().clone()))
        {
            fail("issuer clone test failed");
        }
        
        //equalityAndHashCodeTest(attrCert, certWithBaseCertificateID);
    }

    private void equalityAndHashCodeTest(X509AttributeCertificateHolder attrCert, byte[] encoding)
        throws IOException
    {
        if (!attrCert.equals(attrCert))
        {
            fail("same certificate not equal");
        }

        if (!attrCert.getHolder().equals(attrCert.getHolder()))
        {
            fail("same holder not equal");
        }

        if (!attrCert.getIssuer().equals(attrCert.getIssuer()))
        {
            fail("same issuer not equal");
        }

        if (attrCert.getHolder().equals(attrCert.getIssuer()))
        {
            fail("wrong holder equal");
        }

        if (attrCert.getIssuer().equals(attrCert.getHolder()))
        {
            fail("wrong issuer equal");
        }

        X509AttributeCertificateHolder attrCert2 = new X509AttributeCertificateHolder(encoding);

        if (attrCert2.getHolder().hashCode() != attrCert.getHolder().hashCode())
        {
            fail("holder hashCode test failed");
        }

        if (!attrCert2.getHolder().equals(attrCert.getHolder()))
        {
            fail("holder equals test failed");
        }

        if (attrCert2.getIssuer().hashCode() != attrCert.getIssuer().hashCode())
        {
            fail("issuer hashCode test failed");
        }

        if (!attrCert2.getIssuer().equals(attrCert.getIssuer()))
        {
            fail("issuer equals test failed");
        }
    }

    private void testGenerateWithCert()
        throws Exception
    {
        CertificateFactory          fact = CertificateFactory.getInstance("X.509","BC");
        X509Certificate             iCert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(signCert));
        
        //
        // a sample key pair.
        //
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        //
        // set up the keys
        //
        PrivateKey          privKey;
        PublicKey           pubKey;

        KeyFactory  kFact = KeyFactory.getInstance("RSA", "BC");

        privKey = kFact.generatePrivate(RSA_PRIVATE_KEY_SPEC);
        pubKey = kFact.generatePublic(pubKeySpec);
        
        X509v2AttributeCertificateBuilder gen = new X509v2AttributeCertificateBuilder(
            new AttributeCertificateHolder(new JcaX509CertificateHolder(iCert)),
            new AttributeCertificateIssuer(new X500Name("cn=test")),
            BigInteger.ONE,
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000));

        // the actual attributes
        GeneralName roleName = new GeneralName(GeneralName.rfc822Name, "DAU123456789");
        ASN1EncodableVector roleSyntax = new ASN1EncodableVector();
        roleSyntax.add(roleName);

        // roleSyntax OID: 2.5.24.72;

        gen.addAttribute(new ASN1ObjectIdentifier("2.5.24.72"), new DERSequence(roleSyntax));

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider(BC).build(privKey);

        X509AttributeCertificateHolder aCert = gen.build(sigGen);
        
        if (!aCert.isValidOn(new Date()))
        {
            fail("certificate invalid");
        }
        
        if (!aCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(pubKey)))
        {
            fail("certificate signature not valid");
        }
        
        AttributeCertificateHolder holder = aCert.getHolder();
        
        if (holder.getEntityNames() != null)
        {
            fail("entity names set when none expected");
        }
        
        if (!holder.getSerialNumber().equals(iCert.getSerialNumber()))
        {
            fail("holder serial number doesn't match");
        }

        if (!holder.getIssuer()[0].equals(X500Name.getInstance(iCert.getIssuerX500Principal().getEncoded())))
        {
            fail("holder issuer doesn't match");
        }
        
        if (!holder.match(new JcaX509CertificateHolder(iCert)))
        {
            fail("generated holder not matching holder certificate");
        }
        
        Attribute[] attrs = aCert.getAttributes(new ASN1ObjectIdentifier("2.5.24.72"));
        
        if (attrs == null)
        {
            fail("attributes related to 2.5.24.72 not found");
        }
        
        Attribute attr = attrs[0];
        
        if (!attr.getAttrType().getId().equals("2.5.24.72"))
        {
            fail("attribute oid mismatch");
        }
        
        ASN1Encodable[] values = attr.getAttrValues().toArray();
        
        GeneralName role = GeneralNames.getInstance(values[0]).getNames()[0];
        
        if (role.getTagNo() != GeneralName.rfc822Name)
        {
            fail("wrong general name type found in role");
        }
        
        if (!((ASN1String)role.getName()).getString().equals("DAU123456789"))
        {
            fail("wrong general name value found in role");
        }
        
        X509Certificate             sCert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(holderCertWithBaseCertificateID));
        
        if (holder.match(new JcaX509CertificateHolder(sCert)))
        {
            fail("generated holder matching wrong certificate");
        }

        equalityAndHashCodeTest(aCert, aCert.getEncoded());
    }
    
    private void testGenerateWithPrincipal()
        throws Exception
    {
        CertificateFactory          fact = CertificateFactory.getInstance("X.509","BC");
        X509Certificate             iCert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(signCert));
        
        //
        // a sample key pair.
        //
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));
    
        //
        // set up the keys
        //
        PrivateKey          privKey;
        PublicKey           pubKey;
    
        KeyFactory  kFact = KeyFactory.getInstance("RSA", "BC");
    
        privKey = kFact.generatePrivate(RSA_PRIVATE_KEY_SPEC);
        pubKey = kFact.generatePublic(pubKeySpec);
        
        X509v2AttributeCertificateBuilder gen = new X509v2AttributeCertificateBuilder(
            new AttributeCertificateHolder(new JcaX509CertificateHolder(iCert).getSubject()),
            new AttributeCertificateIssuer(new X500Name("cn=test")),
            BigInteger.ONE,
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000));
        
        // the actual attributes
        GeneralName roleName = new GeneralName(GeneralName.rfc822Name, "DAU123456789");
        ASN1EncodableVector roleSyntax = new ASN1EncodableVector();
        roleSyntax.add(roleName);
    
        // roleSyntax OID: 2.5.24.72
    
        gen.addAttribute(new ASN1ObjectIdentifier("2.5.24.72"), new DERSequence(roleSyntax));

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider(BC).build(privKey);

        X509AttributeCertificateHolder aCert = gen.build(sigGen);
        
        if (!aCert.isValidOn(new Date()))
        {
            fail("certificate invalid");
        }
        
        if (!aCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(pubKey)))
        {
            fail("certificate signature not valid");
        }
        
        AttributeCertificateHolder holder = aCert.getHolder();
        
        if (holder.getEntityNames() == null)
        {
            fail("entity names not set when expected");
        }
        
        if (holder.getSerialNumber() != null)
        {
            fail("holder serial number found when none expected");
        }
    
        if (holder.getIssuer() != null)
        {
            fail("holder issuer found when none expected");
        }
        
        if (!holder.match(new JcaX509CertificateHolder(iCert)))
        {
            fail("generated holder not matching holder certificate");
        }
        
        X509Certificate             sCert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(holderCertWithBaseCertificateID));
        
        if (holder.match(sCert))
        {
            fail("principal generated holder matching wrong certificate");
        }

        equalityAndHashCodeTest(aCert, aCert.getEncoded());
    }
    
    public void performTest()
        throws Exception
    {
        X509AttributeCertificateHolder    aCert = new X509AttributeCertificateHolder(attrCert);
        CertificateFactory          fact = CertificateFactory.getInstance("X.509","BC");
        X509Certificate             sCert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(signCert));
        
        if (!aCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(sCert)))
        {
            fail("certificate signature not valid");
        }

        //
        // search test
        //
        
        List      list = new ArrayList();
        
        list.add(sCert);

        Store store = new JcaCertStore(list);
        
        Collection certs = store.getMatches(aCert.getIssuer());
        if (certs.size() != 1 || !certs.contains(new JcaX509CertificateHolder(sCert)))
        {
            fail("sCert not found by issuer");
        }
        
        Attribute[] attrs = aCert.getAttributes(new ASN1ObjectIdentifier("1.3.6.1.4.1.6760.8.1.1"));
        if (attrs == null || attrs.length != 1)
        {
            fail("attribute not found");
        }

        //
        // reencode test
        //
        aCert = new X509AttributeCertificateHolder(aCert.getEncoded());
        
        if (!aCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(sCert)))
        {
            fail("certificate signature not valid");
        }

        X509AttributeCertificateHolder saCert = new X509AttributeCertificateHolder(aCert.getEncoded());
        
        if (!aCert.getNotAfter().equals(saCert.getNotAfter()))
        {
            fail("failed date comparison");
        }
        
        // base generator test
        
        //
        // a sample key pair.
        //
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeySpec privKeySpec = RSA_PRIVATE_KEY_SPEC;

        //
        // set up the keys
        //
        PrivateKey          privKey;
        PublicKey           pubKey;

        KeyFactory  kFact = KeyFactory.getInstance("RSA", "BC");

        privKey = kFact.generatePrivate(privKeySpec);
        pubKey = kFact.generatePublic(pubKeySpec);
        
        X509v2AttributeCertificateBuilder gen = new X509v2AttributeCertificateBuilder(
            aCert.getHolder(),
            aCert.getIssuer(),
            aCert.getSerialNumber(),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000));

        gen.addAttribute(attrs[0].getAttrType(), attrs[0].getAttributeValues());

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider(BC).build(privKey);

        aCert = gen.build(sigGen);
        
        if (!aCert.isValidOn(new Date()))
        {
            fail("certificate not valid");
        }
        
        if (!aCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(pubKey)))
        {
            fail("signature not valid");
        }
        
        // as the issuer is the same this should still work (even though it is not
        // technically correct
        
        certs = store.getMatches(aCert.getIssuer());
        if (certs.size() != 1 || !certs.contains(new JcaX509CertificateHolder(sCert)))
        {
            fail("sCert not found by issuer");
        }
        
        attrs = aCert.getAttributes(new ASN1ObjectIdentifier("1.3.6.1.4.1.6760.8.1.1"));
        if (attrs == null || attrs.length != 1)
        {
            fail("attribute not found");
        }
        
        //
        // reencode test
        //
        aCert = new X509AttributeCertificateHolder(aCert.getEncoded());
        
        if (!aCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(pubKey)))
        {
            fail("signature not valid");
        }
        
        AttributeCertificateIssuer  issuer = aCert.getIssuer();
        
        X500Name[] principals = issuer.getNames();
        
        //
        // test holder
        //
        AttributeCertificateHolder holder = aCert.getHolder();
        
        if (holder.getEntityNames() == null)
        {
            fail("entity names not set");
        }
        
        if (holder.getSerialNumber() != null)
        {
            fail("holder serial number set when none expected");
        }

        if (holder.getIssuer() != null)
        {
            fail("holder issuer set when none expected");
        }
        
        principals = holder.getEntityNames();

        X500Principal principal0 = new X500Principal(principals[0].getEncoded());
        if (!principal0.toString().equals("C=US, O=vt, OU=Class 2, OU=Virginia Tech User, CN=Markus Lorch (mlorch), EMAILADDRESS=mlorch@vt.edu"))
        {
            fail("principal[0] for entity names don't match");
        }

        //
        // extension test
        //
        
        if (aCert.hasExtensions())
        {
            fail("hasExtensions true with no extensions");
        }
        
        gen.addExtension(new ASN1ObjectIdentifier("1.1"), true, new DEROctetString(new byte[10]));
        
        gen.addExtension(new ASN1ObjectIdentifier("2.2"), false, new DEROctetString(new byte[20]));
        
        aCert = gen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privKey));
        
        Set exts = aCert.getCriticalExtensionOIDs();
        
        if (exts.size() != 1 || !exts.contains(new ASN1ObjectIdentifier("1.1")))
        {
            fail("critical extension test failed");
        }

        exts = aCert.getNonCriticalExtensionOIDs();
        
        if (exts.size() != 1 || !exts.contains(new ASN1ObjectIdentifier("2.2")))
        {
            fail("non-critical extension test failed");
        }
        
        if (aCert.getCriticalExtensionOIDs().isEmpty())
        {
            fail("critical extensions not found");
        }
        
        Extension ext = aCert.getExtension(new ASN1ObjectIdentifier("1.1"));
        ASN1Encodable extValue = ext.getParsedValue();
        
        if (!extValue.equals(new DEROctetString(new byte[10])))
        {
            fail("wrong extension value found for 1.1");
        }
        
        testCertWithBaseCertificateID();
        testGenerateWithCert();
        testGenerateWithPrincipal();

        aCert = new X509v2AttributeCertificateBuilder(aCert).build(
            new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey));

        if (!aCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(pubKey)))
        {
            fail("signature not valid");
        }

    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AttrCertTest());
    }
}
