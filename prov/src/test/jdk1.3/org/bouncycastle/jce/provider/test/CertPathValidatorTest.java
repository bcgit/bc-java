package org.bouncycastle.jce.provider.test;
 
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.jce.cert.CertPath;
import org.bouncycastle.jce.cert.CertPathValidator;
import org.bouncycastle.jce.cert.CertPathValidatorException;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertificateFactory;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import org.bouncycastle.jce.cert.PKIXCertPathValidatorResult;
import org.bouncycastle.jce.cert.PKIXParameters;
import org.bouncycastle.jce.cert.PolicyNode;
import org.bouncycastle.jce.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class CertPathValidatorTest
    extends SimpleTest
{
    private byte[] AC_PR = Base64.decode(
           "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlFU1RDQ0F6R2dBd0lC"
        + "QWdJQkJUQU5CZ2txaGtpRzl3MEJBUVVGQURDQnRERUxNQWtHQTFVRUJoTUNR"
        + "bEl4DQpFekFSQmdOVkJBb1RDa2xEVUMxQ2NtRnphV3d4UFRBN0JnTlZCQXNU"
        + "TkVsdWMzUnBkSFYwYnlCT1lXTnBiMjVoDQpiQ0JrWlNCVVpXTnViMnh2WjJs"
        + "aElHUmhJRWx1Wm05eWJXRmpZVzhnTFNCSlZFa3hFVEFQQmdOVkJBY1RDRUp5"
        + "DQpZWE5wYkdsaE1Rc3dDUVlEVlFRSUV3SkVSakV4TUM4R0ExVUVBeE1vUVhW"
        + "MGIzSnBaR0ZrWlNCRFpYSjBhV1pwDQpZMkZrYjNKaElGSmhhWG9nUW5KaGMy"
        + "bHNaV2x5WVRBZUZ3MHdNakEwTURReE9UTTVNREJhRncwd05UQTBNRFF5DQpN"
        + "elU1TURCYU1HRXhDekFKQmdOVkJBWVRBa0pTTVJNd0VRWURWUVFLRXdwSlEx"
        + "QXRRbkpoYzJsc01UMHdPd1lEDQpWUVFERXpSQmRYUnZjbWxrWVdSbElFTmxj"
        + "blJwWm1sallXUnZjbUVnWkdFZ1VISmxjMmxrWlc1amFXRWdaR0VnDQpVbVZ3"
        + "ZFdKc2FXTmhNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJD"
        + "Z0tDQVFFQXMwc0t5NGsrDQp6b016aldyMTQxeTVYQ045UGJMZERFQXN2cjZ4"
        + "Z0NCN1l5bEhIQ1NBYmpGR3dOQ0R5NlVxN1h0VjZ6UHdIMXpGDQpFWENlS3Jm"
        + "UUl5YXBXSEZ4V1VKajBMblFrY1RZM1FOR1huK0JuVk9EVTZDV3M1c3NoZktH"
        + "RXZyVlQ1Z214V1NmDQp4OFlsdDgzY1dwUE1QZzg3VDlCaHVIbHQzazh2M2Ev"
        + "NmRPbmF2dytOYTAyZExBaDBlNzZqcCtQUS9LK0pHZlBuDQphQjVVWURrZkd0"
        + "em5uTTNBV01tY3VJK0o0ek5OMDZaa3ZnbDFsdEo2UU1qcnZEUFlSak9ndDlT"
        + "cklpY1NmbEo4DQptVDdHWGRRaXJnQUNXc3g1QURBSklRK253TU1vNHlyTUtx"
        + "SlFhNFFDMHhhT0QvdkdVcG9SaDQzT0FTZFp3c3YvDQpPWFlybmVJeVAwVCs4"
        + "UUlEQVFBQm80RzNNSUcwTUQwR0ExVWRId1EyTURRd01xQXdvQzZHTEdoMGRI"
        + "QTZMeTloDQpZM0poYVhvdWFXTndZbkpoYzJsc0xtZHZkaTVpY2k5TVExSmhZ"
        + "M0poYVhvdVkzSnNNQklHQTFVZElBUUxNQWt3DQpCd1lGWUV3QkFRRXdIUVlE"
        + "VlIwT0JCWUVGREpUVFlKNE9TWVB5T09KZkVMZXhDaHppK2hiTUI4R0ExVWRJ"
        + "d1FZDQpNQmFBRklyNjhWZUVFUk0xa0VMNlYwbFVhUTJreFBBM01BNEdBMVVk"
        + "RHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CDQpBZjhFQlRBREFRSC9NQTBHQ1Nx"
        + "R1NJYjNEUUVCQlFVQUE0SUJBUUJRUFNoZ1lidnFjaWV2SDVVb3ZMeXhkbkYr"
        + "DQpFcjlOeXF1SWNkMnZ3Y0N1SnpKMkQ3WDBUcWhHQ0JmUEpVVkdBVWorS0NP"
        + "SDFCVkgva1l1OUhsVHB1MGtKWFBwDQpBQlZkb2hJUERqRHhkbjhXcFFSL0Yr"
        + "ejFDaWtVcldIMDR4eTd1N1p6UUpLSlBuR0loY1FpOElyRm1PYkllMEc3DQpY"
        + "WTZPTjdPRUZxY21KTFFHWWdtRzFXMklXcytQd1JwWTdENGhLVEFoVjFSNkVv"
        + "amE1L3BPcmVDL09kZXlQWmVxDQo1SUZTOUZZZk02U0Npd2hrK3l2Q1FHbVo0"
        + "YzE5SjM0ZjVFYkRrK1NQR2tEK25EQ0E3L3VMUWNUMlJURE14SzBaDQpuZlo2"
        + "Nm1Sc0ZjcXRGaWdScjVFcmtKZDdoUVV6eHNOV0VrNzJEVUFIcVgvNlNjeWtt"
        + "SkR2V0plSUpqZlcNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg==");

    private byte[] AC_RAIZ_ICPBRASIL = Base64.decode(
          "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlFdURDQ0E2Q2dBd0lC"
        + "QWdJQkJEQU5CZ2txaGtpRzl3MEJBUVVGQURDQnRERUxNQWtHQTFVRUJoTUNR"
        + "bEl4DQpFekFSQmdOVkJBb1RDa2xEVUMxQ2NtRnphV3d4UFRBN0JnTlZCQXNU"
        + "TkVsdWMzUnBkSFYwYnlCT1lXTnBiMjVoDQpiQ0JrWlNCVVpXTnViMnh2WjJs"
        + "aElHUmhJRWx1Wm05eWJXRmpZVzhnTFNCSlZFa3hFVEFQQmdOVkJBY1RDRUp5"
        + "DQpZWE5wYkdsaE1Rc3dDUVlEVlFRSUV3SkVSakV4TUM4R0ExVUVBeE1vUVhW"
        + "MGIzSnBaR0ZrWlNCRFpYSjBhV1pwDQpZMkZrYjNKaElGSmhhWG9nUW5KaGMy"
        + "bHNaV2x5WVRBZUZ3MHdNVEV4TXpBeE1qVTRNREJhRncweE1URXhNekF5DQpN"
        + "elU1TURCYU1JRzBNUXN3Q1FZRFZRUUdFd0pDVWpFVE1CRUdBMVVFQ2hNS1NV"
        + "TlFMVUp5WVhOcGJERTlNRHNHDQpBMVVFQ3hNMFNXNXpkR2wwZFhSdklFNWhZ"
        + "Mmx2Ym1Gc0lHUmxJRlJsWTI1dmJHOW5hV0VnWkdFZ1NXNW1iM0p0DQpZV05o"
        + "YnlBdElFbFVTVEVSTUE4R0ExVUVCeE1JUW5KaGMybHNhV0V4Q3pBSkJnTlZC"
        + "QWdUQWtSR01URXdMd1lEDQpWUVFERXloQmRYUnZjbWxrWVdSbElFTmxjblJw"
        + "Wm1sallXUnZjbUVnVW1GcGVpQkNjbUZ6YVd4bGFYSmhNSUlCDQpJakFOQmdr"
        + "cWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBd1BNdWR3WC9odm0r"
        + "VWgyYi9sUUFjSFZBDQppc2FtYUxrV2Rrd1A5L1MvdE9LSWdSckw2T3krWklH"
        + "bE9VZGQ2dVl0azlNYS8zcFVwZ2NmTkFqMHZZbTVnc3lqDQpRbzllbXNjK3g2"
        + "bTRWV3drOWlxTVpTQ0s1RVFrQXEvVXQ0bjdLdUxFMStnZGZ0d2RJZ3hmVXNQ"
        + "dDRDeU5yWTUwDQpRVjU3S00yVVQ4eDVycm16RWpyN1RJQ0dwU1VBbDJnVnFl"
        + "NnhhaWkrYm1ZUjFRcm1XYUJTQUc1OUxya3Jqcll0DQpiUmhGYm9VRGUxREsr"
        + "NlQ4czVMNms4Yzhva3BiSHBhOXZlTXp0RFZDOXNQSjYwTVdYaDZhblZLbzFV"
        + "Y0xjYlVSDQp5RWVOdlpuZVZSS0FBVTZvdXdkakR2d2xzYUt5ZEZLd2VkMFRv"
        + "UTQ3Ym1VS2djbSt3VjNlVFJrMzZVT25Ud0lEDQpBUUFCbzRIU01JSFBNRTRH"
        + "QTFVZElBUkhNRVV3UXdZRllFd0JBUUF3T2pBNEJnZ3JCZ0VGQlFjQ0FSWXNh"
        + "SFIwDQpjRG92TDJGamNtRnBlaTVwWTNCaWNtRnphV3d1WjI5MkxtSnlMMFJR"
        + "UTJGamNtRnBlaTV3WkdZd1BRWURWUjBmDQpCRFl3TkRBeW9EQ2dMb1lzYUhS"
        + "MGNEb3ZMMkZqY21GcGVpNXBZM0JpY21GemFXd3VaMjkyTG1KeUwweERVbUZq"
        + "DQpjbUZwZWk1amNtd3dIUVlEVlIwT0JCWUVGSXI2OFZlRUVSTTFrRUw2VjBs"
        + "VWFRMmt4UEEzTUE4R0ExVWRFd0VCDQovd1FGTUFNQkFmOHdEZ1lEVlIwUEFR"
        + "SC9CQVFEQWdFR01BMEdDU3FHU0liM0RRRUJCUVVBQTRJQkFRQVpBNWMxDQpV"
        + "L2hnSWg2T2NnTEFmaUpnRldwdm1EWldxbFYzMC9iSEZwajhpQm9iSlNtNXVE"
        + "cHQ3VGlyWWgxVXhlM2ZRYUdsDQpZakplKzl6ZCtpelBSYkJxWFBWUUEzNEVY"
        + "Y3drNHFwV3VmMWhIcmlXZmRyeDhBY3FTcXI2Q3VRRndTcjc1Rm9zDQpTemx3"
        + "REFEYTcwbVQ3d1pqQW1RaG5aeDJ4SjZ3ZldsVDlWUWZTLy9KWWVJYzdGdWUy"
        + "Sk5MZDAwVU9TTU1haUsvDQp0NzllbktOSEVBMmZ1cEgzdkVpZ2Y1RWg0YlZB"
        + "TjVWb2hyVG02TVk1M3g3WFFaWnIxTUU3YTU1bEZFblNlVDB1DQptbE9BalIy"
        + "bUFidlNNNVg1b1NaTnJtZXRkenlUajJmbENNOENDN01MYWIwa2tkbmdSSWxV"
        + "QkdIRjEvUzVubVBiDQpLKzlBNDZzZDMzb3FLOG44DQotLS0tLUVORCBDRVJU"
        + "SUZJQ0FURS0tLS0tDQo=");

    private byte[] schefer = Base64.decode(
          "MIIEnDCCBAWgAwIBAgICIPAwDQYJKoZIhvcNAQEEBQAwgcAxCzAJBgNVBAYT"
        + "AkRFMQ8wDQYDVQQIEwZIRVNTRU4xGDAWBgNVBAcTDzY1MDA4IFdpZXNiYWRl"
        + "bjEaMBgGA1UEChMRU0NIVUZBIEhPTERJTkcgQUcxGjAYBgNVBAsTEVNDSFVG"
        + "QSBIT0xESU5HIEFHMSIwIAYDVQQDExlJbnRlcm5ldCBCZW51dHplciBTZXJ2"
        + "aWNlMSowKAYJKoZIhvcNAQkBFht6ZXJ0aWZpa2F0QHNjaHVmYS1vbmxpbmUu"
        + "ZGUwHhcNMDQwMzMwMTEwODAzWhcNMDUwMzMwMTEwODAzWjCBnTELMAkGA1UE"
        + "BhMCREUxCjAIBgNVBAcTASAxIzAhBgNVBAoTGlNIUyBJbmZvcm1hdGlvbnNz"
        + "eXN0ZW1lIEFHMRwwGgYDVQQLExM2MDAvMDU5NDktNjAwLzA1OTQ5MRgwFgYD"
        + "VQQDEw9TY2hldHRlciBTdGVmYW4xJTAjBgkqhkiG9w0BCQEWFlN0ZWZhbi5T"
        + "Y2hldHRlckBzaHMuZGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJD0"
        + "95Bi76fkAMjJNTGPDiLPHmZXNsmakngDeS0juzKMeJA+TjXFouhYh6QyE4Bl"
        + "Nf18fT4mInlgLefwf4t6meIWbiseeTo7VQdM+YrbXERMx2uHsRcgZMsiMYHM"
        + "kVfYMK3SMJ4nhCmZxrBkoTRed4gXzVA1AA8YjjTqMyyjvt4TAgMBAAGjggHE"
        + "MIIBwDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIEsDALBgNVHQ8EBAMC"
        + "BNAwOQYJYIZIAYb4QgENBCwWKlplcnRpZmlrYXQgbnVyIGZ1ZXIgU0NIVUZB"
        + "LU9ubGluZSBndWVsdGlnLjAdBgNVHQ4EFgQUXReirhBfg0Yhf6MsBWoo/nPa"
        + "hGwwge0GA1UdIwSB5TCB4oAUf2UyCaBV9JUeG9lS1Yo6OFBUdEKhgcakgcMw"
        + "gcAxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIEwZIRVNTRU4xGDAWBgNVBAcTDzY1"
        + "MDA4IFdpZXNiYWRlbjEaMBgGA1UEChMRU0NIVUZBIEhPTERJTkcgQUcxGjAY"
        + "BgNVBAsTEVNDSFVGQSBIT0xESU5HIEFHMSIwIAYDVQQDExlJbnRlcm5ldCBC"
        + "ZW51dHplciBTZXJ2aWNlMSowKAYJKoZIhvcNAQkBFht6ZXJ0aWZpa2F0QHNj"
        + "aHVmYS1vbmxpbmUuZGWCAQAwIQYDVR0RBBowGIEWU3RlZmFuLlNjaGV0dGVy"
        + "QHNocy5kZTAmBgNVHRIEHzAdgRt6ZXJ0aWZpa2F0QHNjaHVmYS1vbmxpbmUu"
        + "ZGUwDQYJKoZIhvcNAQEEBQADgYEAWzZtN9XQ9uyrFXqSy3hViYwV751+XZr0"
        + "YH5IFhIS+9ixNAu8orP3bxqTaMhpwoU7T/oSsyGGSkb3fhzclgUADbA2lrOI"
        + "GkeB/m+FArTwRbwpqhCNTwZywOp0eDosgPjCX1t53BB/m/2EYkRiYdDGsot0"
        + "kQPOVGSjQSQ4+/D+TM8=");

    public void performTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // initialise CertStore
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.finalCertBin));
        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.rootCrlBin));
        X509CRL interCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.interCrlBin));
        List list = new ArrayList();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);
        list.add(rootCrl);
        list.add(interCrl);
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp);
        Calendar validDate = Calendar.getInstance();
        validDate.set(2002,2,21,2,21,10);

            //validating path
        List certchain = new ArrayList();
        certchain.add(finalCert);
        certchain.add(interCert);
        CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate.getTime());
        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult) cpv.validate(cp, param);
        PolicyNode policyTree = result.getPolicyTree();
        PublicKey subjectPublicKey = result.getPublicKey();

        if (!subjectPublicKey.equals(finalCert.getPublicKey()))
        {
            fail("wrong public key returned");
        }

        //
        // invalid path containing a valid one test
        //
        try
        {
                // initialise CertStore
            rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_RAIZ_ICPBRASIL));
            interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_PR));
            finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(schefer));
    
            list = new ArrayList();
            list.add(rootCert);
            list.add(interCert);
            list.add(finalCert);

            ccsp = new CollectionCertStoreParameters(list);
            store = CertStore.getInstance("Collection", ccsp);
            validDate = Calendar.getInstance();
            validDate.set(2004,2,21,2,21,10);
    
                //validating path
            certchain = new ArrayList();
            certchain.add(finalCert);
            certchain.add(interCert);
            cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
            trust = new HashSet();
            trust.add(new TrustAnchor(rootCert, null));

            cpv = CertPathValidator.getInstance("PKIX","BC");
            param = new PKIXParameters(trust);
            param.addCertStore(store);
            param.setRevocationEnabled(false);
            param.setDate(validDate.getTime());
            
            result =(PKIXCertPathValidatorResult) cpv.validate(cp, param);
            policyTree = result.getPolicyTree();
            subjectPublicKey = result.getPublicKey();
            
            fail("Invalid path validated");
        }
        catch (Exception e)
        {
            if (e instanceof CertPathValidatorException 
                && e.getMessage().startsWith("Could not validate certificate signature."))
            {
                return;
            }
            fail("unexpected exception", e);
        }
    }

    public String getName()
    {
        return "CertPathValidator";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathValidatorTest());
    }
}

