package org.bouncycastle.asn1.test;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERNumericString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.DERVisibleString;
import org.bouncycastle.asn1.cryptopro.ECGOST3410ParamSetParameters;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.cryptopro.GOST3410ParamSetParameters;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;

import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.IDEACBCPar;
import org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.CrlID;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertIssuer;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.CertificatePair;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.IetfAttrSyntax;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.NoticeReference;
import org.bouncycastle.asn1.x509.ObjectDigestInfo;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Target;
import org.bouncycastle.asn1.x509.TargetInformation;
import org.bouncycastle.asn1.x509.Targets;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.bouncycastle.asn1.x509.sigi.NameOrPseudonym;
import org.bouncycastle.asn1.x509.sigi.PersonalData;
import org.bouncycastle.asn1.x9.DHDomainParameters;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.asn1.x9.DHValidationParms;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Base64;

public class GetInstanceTest
    extends TestCase
{
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

    byte[]  cert1 = Base64.decode(
        "MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
            + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
            + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
            + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
            + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
            + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
            + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
            + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
            + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
            + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
            + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
            + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
            + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
            + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
            + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
            + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
            + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
            + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF"
            + "5/8=");

    private byte[] v2CertList = Base64.decode(
          "MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT"
        + "F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy"
        + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw"
        + "MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw"
        + "MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw"
        + "MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw"
        + "MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw"
        + "MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw"
        + "MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw"
        + "NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw"
        + "NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF"
        + "AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ"
        + "wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt"
        + "JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v");

    private static final Object[] NULL_ARGS = new Object[] { null };

    private void doFullGetInstanceTest(Class clazz, ASN1Object o1)
        throws Exception
    {
        Method m;

        try
        {
            m = clazz.getMethod("getInstance", Object.class);
        }
        catch (NoSuchMethodException e)
        {
            fail("no getInstance method found");
            return;
        }

        ASN1Object o2 = (ASN1Object)m.invoke(clazz, NULL_ARGS);
        if (o2 != null)
        {
            fail(clazz.getName() + " null failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1);

        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " equality failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1.getEncoded());
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " encoded equality failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1.toASN1Primitive());
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " sequence equality failed");
        }

        try
        {
            m = clazz.getMethod("getInstance", ASN1TaggedObject.class, Boolean.TYPE);
        }
        catch (NoSuchMethodException e)
        {
            return;
        }

        ASN1TaggedObject t = new DERTaggedObject(true, 0, o1);
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(true, 0, o1.toASN1Primitive());
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = ASN1TaggedObject.getInstance(t.getEncoded());
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(false, 0, o1);
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(false, 0, o1.toASN1Primitive());
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = ASN1TaggedObject.getInstance(t.getEncoded());
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }
    }

    public void testGetInstance()
        throws Exception
    {
        doFullGetInstanceTest(DERPrintableString.class, new DERPrintableString("hello world"));
        doFullGetInstanceTest(DERBMPString.class, new DERBMPString("hello world"));
        doFullGetInstanceTest(DERUTF8String.class, new DERUTF8String("hello world"));
        doFullGetInstanceTest(DERUniversalString.class, new DERUniversalString(new byte[20]));
        doFullGetInstanceTest(DERIA5String.class, new DERIA5String("hello world"));
        doFullGetInstanceTest(DERGeneralString.class, new DERGeneralString("hello world"));
        doFullGetInstanceTest(DERNumericString.class, new DERNumericString("hello world"));
        doFullGetInstanceTest(DERNumericString.class, new DERNumericString("99999", true));
        doFullGetInstanceTest(DERT61String.class, new DERT61String("hello world"));
        doFullGetInstanceTest(DERVisibleString.class, new DERVisibleString("hello world"));

        doFullGetInstanceTest(ASN1Integer.class, new ASN1Integer(1));
        doFullGetInstanceTest(ASN1GeneralizedTime.class, new ASN1GeneralizedTime(new Date()));
        doFullGetInstanceTest(ASN1UTCTime.class, new ASN1UTCTime(new Date()));
        doFullGetInstanceTest(ASN1Enumerated.class, new ASN1Enumerated(1));

        SignedData.getInstance(null);
        Time.getInstance(null);
        Time.getInstance(null);

        ECGOST3410ParamSetParameters.getInstance(null);
        ECGOST3410ParamSetParameters.getInstance(null);
        GOST28147Parameters.getInstance(null);
        GOST28147Parameters.getInstance(null);
        GOST3410ParamSetParameters.getInstance(null);
        GOST3410ParamSetParameters.getInstance(null);
        GOST3410PublicKeyAlgParameters.getInstance(null);
        GOST3410PublicKeyAlgParameters.getInstance(null);

        ASN1EncodableVector postalAddr = new ASN1EncodableVector();

        postalAddr.add(new DERUTF8String("line 1"));
        postalAddr.add(new DERUTF8String("line 2"));

        Vector v = new Vector();

        v.add(Integers.valueOf(1));
        v.add(BigInteger.valueOf(2));
        NoticeReference noticeReference = new NoticeReference("BC", v);

        CAST5CBCParameters.getInstance(null);
        IDEACBCPar.getInstance(null);
        PublicKeyAndChallenge.getInstance(null);
        BasicOCSPResponse.getInstance(null);
        BasicOCSPResponse.getInstance(null);

        doFullGetInstanceTest(CertID.class, new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new DEROctetString(new byte[1]), new DEROctetString(new byte[1]), new ASN1Integer(1)));

        CertStatus.getInstance(null);
        CertStatus.getInstance(null);
        CrlID.getInstance(null);
        OCSPRequest.getInstance(null);
        OCSPRequest.getInstance(null);
        OCSPResponse.getInstance(null);
        OCSPResponse.getInstance(null);
        OCSPResponseStatus.getInstance(null);
        Request.getInstance(null);
        Request.getInstance(null);
        ResponderID.getInstance(null);
        ResponderID.getInstance(null);
        ResponseBytes.getInstance(null);
        ResponseBytes.getInstance(null);
        ResponseData.getInstance(null);
        ResponseData.getInstance(null);
        RevokedInfo.getInstance(null);
        RevokedInfo.getInstance(null);
        Signature.getInstance(null);
        Signature.getInstance(null);
        SingleResponse.getInstance(null);
        SingleResponse.getInstance(null);
        TBSRequest.getInstance(null);
        TBSRequest.getInstance(null);

        AuthenticatedSafe.getInstance(null);
        CertificationRequestInfo.getInstance(null);
        CertificationRequest.getInstance(null);

        DHParameter.getInstance(null);

        EncryptedPrivateKeyInfo.getInstance(null);
        AlgorithmIdentifier.getInstance(null);

        MacData.getInstance(null);
        PBEParameter.getInstance(null);
        PBES2Parameters.getInstance(null);
        PBKDF2Params.getInstance(null);
        Pfx.getInstance(null);
        PKCS12PBEParams.getInstance(null);
        PrivateKeyInfo.getInstance(null);
        PrivateKeyInfo.getInstance(null);
        RC2CBCParameter.getInstance(null);
        RSAESOAEPparams.getInstance(null);
        RSAPrivateKey.getInstance(null);
        RSAPrivateKey.getInstance(null);
        RSASSAPSSparams.getInstance(null);
        SafeBag.getInstance(null);
        SignedData.getInstance(null);

        ECPrivateKey.getInstance(null);

        DirectoryString.getInstance(null);
        DirectoryString.getInstance(null);
        RDN.getInstance(null);
        X500Name.getInstance(null);
        X500Name.getInstance(null);
        AccessDescription.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        AttCertIssuer.getInstance(null);
        AttCertIssuer.getInstance(null);
        AttCertValidityPeriod.getInstance(null);
        AttributeCertificateInfo.getInstance(null);
        AttributeCertificateInfo.getInstance(null);
        AttributeCertificate.getInstance(null);

        AuthorityInformationAccess.getInstance(null);
        AuthorityKeyIdentifier.getInstance(null);
        AuthorityKeyIdentifier.getInstance(null);
        BasicConstraints.getInstance(null);
        BasicConstraints.getInstance(null);
        Certificate.getInstance(null);
        Certificate.getInstance(null);
        CertificateList.getInstance(null);
        CertificateList.getInstance(null);
        CertificatePair.getInstance(null);
        CertificatePolicies.getInstance(null);
        CertificatePolicies.getInstance(null);
        CRLDistPoint.getInstance(null);
        CRLDistPoint.getInstance(null);
        CRLNumber.getInstance(null);
        CRLReason.getInstance(null);
        DigestInfo.getInstance(null);
        DigestInfo.getInstance(null);
        DisplayText.getInstance(null);
        DisplayText.getInstance(null);
        DistributionPoint.getInstance(null);
        DistributionPoint.getInstance(null);
        DistributionPointName.getInstance(null);
        DistributionPointName.getInstance(null);
        DSAParameter.getInstance(null);
        DSAParameter.getInstance(null);
        ExtendedKeyUsage.getInstance(null);
        ExtendedKeyUsage.getInstance(null);
        Extensions.getInstance(null);
        Extensions.getInstance(null);
        GeneralName.getInstance(null);
        GeneralName.getInstance(null);
        GeneralNames.getInstance(null);
        GeneralNames.getInstance(null);

        GeneralSubtree generalSubtree = new GeneralSubtree(new GeneralName(new X500Name("CN=Test")));
        ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier("1.2.1");
        ObjectDigestInfo objectDigestInfo = new ObjectDigestInfo(ObjectDigestInfo.otherObjectDigest, algOid, new AlgorithmIdentifier(algOid), new byte[20]);

        doFullGetInstanceTest(GeneralSubtree.class, generalSubtree);
        doFullGetInstanceTest(Holder.class, new Holder(objectDigestInfo));
        IetfAttrSyntax.getInstance(null);
        IssuerSerial.getInstance(null);
        IssuerSerial.getInstance(null);
        IssuingDistributionPoint.getInstance(null);
        IssuingDistributionPoint.getInstance(null);
        ASN1BitString.getInstance(null);

        v.clear();
        v.add(generalSubtree);

        doFullGetInstanceTest(NameConstraints.class, new NameConstraints(null, null));
        doFullGetInstanceTest(NoticeReference.class, noticeReference);
        doFullGetInstanceTest(ObjectDigestInfo.class, objectDigestInfo);

        PolicyInformation.getInstance(null);
        PolicyMappings.getInstance(null);
        PolicyQualifierInfo.getInstance(null);
        PrivateKeyUsagePeriod.getInstance(null);
        doFullGetInstanceTest(RoleSyntax.class, new RoleSyntax(new GeneralNames(new GeneralName(new X500Name("CN=Test"))), new GeneralName(GeneralName.uniformResourceIdentifier, "http://bc")));
        org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(null);

        SubjectDirectoryAttributes.getInstance(null);
        SubjectKeyIdentifier.getInstance(null);
        SubjectKeyIdentifier.getInstance(null);
        SubjectPublicKeyInfo.getInstance(null);
        SubjectPublicKeyInfo.getInstance(null);
        TargetInformation.getInstance(null);
        Target.getInstance(null);
        Targets.getInstance(null);
        TBSCertificate.getInstance(null);
        TBSCertificate.getInstance(null);
        TBSCertificateStructure.getInstance(null);
        TBSCertificateStructure.getInstance(null);
        TBSCertList.CRLEntry.getInstance(null);
        TBSCertList.getInstance(null);
        TBSCertList.getInstance(null);
        Time.getInstance(null);
        Time.getInstance(null);
        doFullGetInstanceTest(UserNotice.class, new UserNotice(noticeReference, "hello world"));
        V2Form.getInstance(null);
        V2Form.getInstance(null);
        X509CertificateStructure.getInstance(null);
        X509CertificateStructure.getInstance(null);
        X509Extensions.getInstance(null);
        X509Extensions.getInstance(null);
        X500Name.getInstance(null);
        X500Name.getInstance(null);
        DHDomainParameters.getInstance(null);
        DHDomainParameters.getInstance(null);
        DHPublicKey.getInstance(null);
        DHPublicKey.getInstance(null);
        DHValidationParms.getInstance(null);
        DHValidationParms.getInstance(null);
        X962Parameters.getInstance(null);
        X962Parameters.getInstance(null);
        X9ECParameters.getInstance(null);
        
        BiometricData.getInstance(null);
        Iso4217CurrencyCode.getInstance(null);
        MonetaryValue.getInstance(null);
        QCStatement.getInstance(null);
        SemanticsInformation.getInstance(null);
        TypeOfBiometricData.getInstance(null);
        NameOrPseudonym.getInstance(null);
        PersonalData.getInstance(null);
    }

    public String getName()
    {
        return "GetInstanceNullTest";
    }
}
