package org.bouncycastle.est.test;

import java.math.BigInteger;
import java.util.Collection;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.est.CSRAttributesResponse;
import org.bouncycastle.est.SimplePKIResponse;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

public class ESTParsingTest
    extends TestCase
{
    private static byte[] cacertsResponse = Base64.decode(
        "MIIMOQYJKoZIhvcNAQcCoIIMKjCCDCYCAQExADALBgkqhkiG9w0BBwGgggwMMIIC" +
            "+zCCAeOgAwIBAgIJAJpY3nUZO3qcMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMT" +
            "EGVzdEV4YW1wbGVDQSBPd08wHhcNMTMwNTA5MDM1MzMxWhcNMTQwNTA5MDM1MzMx" +
            "WjAbMRkwFwYDVQQDExBlc3RFeGFtcGxlQ0EgT3dPMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAwDqpiHopaICubpRqbpEN7LqTIqWELFIA9qDDheHIKuyO" +
            "HW/ZAP7Rl4S5ZU6gaLW/ksseBUxdmox3KNyvtyjehIofTu28eZWhgy6/LCEGWR3P" +
            "K+fgPBA0l0JfJR/8oeXZa70oLVQc3hI4kCeqjFMs+biYH0vp/RluhftyZ5kzQyH1" +
            "EGsRkw1/qUKkTZ8PCF8VFlYfqmUoqsaRTyZbjII4J+Y6/jEG+p7QreW9zcz4sPe8" +
            "3c/uhwMLOWQkZtKsQtgo5CpfYMjuAmk4Q2joQq2vcxlc+WNKHf+wbrDb11ORZril" +
            "9ISlI94oumcRz3uBG1Yg7z83hdDfasmdfbp8gOSNFQIDAQABo0IwQDAPBgNVHRMB" +
            "Af8EBTADAQH/MB0GA1UdDgQWBBQITTKxMqATXrfc4ffpCIbt6Gsz0jAOBgNVHQ8B" +
            "Af8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBACPnQPu5WReUGuCMS0nBOGa2tXh6" +
            "uZP4mS3J1qEfDePam/IiU9ssyYdcDwhVvKMoP4gI/yu4XFqhdpIoy/PyD4T15MT7" +
            "KADCxXkh5rM1IqMui7FvBKLWYGdy9sjEf90wAkBjHBe/TMO1NNw3uELyONSkHIvo" +
            "X0pu6aPmm/moIMyGi46niFse1iWlXXldGLkOQsh0e7U+wpBX07QpOr2KB2+Yf+uA" +
            "KY1SWzEG23bUxXlvcbUMgANDGj5r6z+niKL0VlApip/iCuVEEOcZ91UlmJjVLQWA" +
            "x6ie+v84oM+pIojiGM0C4XWcVlKKEgcMOsN3S4lvm8Ptpq0GLoIJY8NTD20wggMD" +
            "MIIB66ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEGVzdEV4YW1w" +
            "bGVDQSBPd08wHhcNMTMwNTA5MDM1MzMyWhcNMTQwNTA5MDM1MzMyWjAbMRkwFwYD" +
            "VQQDExBlc3RFeGFtcGxlQ0EgTndPMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" +
            "CgKCAQEAnn3rZ3rMJHwf7MD9K4mubxHAvtdnrsQf5OfgtMhRIL4aePNhAdgPyj8C" +
            "loxOgD3UTV+dQ1ViOzVxPN7acikoOnkIdRpjpOpkyMo+KkvHMQXGnQTbsMAv1qWt" +
            "9S12DMpo0GOA1e4Ge3ud5YPOTR/q6PvjN51IEwYKksG7CglwZwB+5JbwhYr2D/0u" +
            "btGltriRVixPWrvt+wz/ITp5rcjh/8RS3LE8tQy3kTNhJF3Y/esR2sSgOiPNgIto" +
            "CATysbaINEPr4MemqML4tDpR/aG9y+8Qe7s1LyMFvDletp2mmBykAC/7nOat/pwU" +
            "lB0sN524D1XAgz8ZKvWrkh+ZaOr3hwIDAQABo1IwUDAOBgNVHQ8BAf8EBAMCBLAw" +
            "HQYDVR0OBBYEFLHEaeZbowSn2Jejizu/uWqyMkI8MB8GA1UdIwQYMBaAFAhNMrEy" +
            "oBNet9zh9+kIhu3oazPSMA0GCSqGSIb3DQEBBQUAA4IBAQCLDkL7aLNV6hSOkIqH" +
            "q+shV9YLO56/tj00vY/jV5skgDHk5d0B+OGortKVuGa57+v0avTrlJns3bNW8Ntv" +
            "zkDEhmd00Ak02aPsi4wRHLFgttUf9HdEHAuTkAESPTU43DiptjkfHhtBMfsFrCkd" +
            "sxWzCz+prDOMHYfUEkhRVV++1zyGEX6ov1Ap2IU2p3E+ASihL/amxTEQAsbwjUTI" +
            "R52zoL6nMPzpbKeZi2M0eEBVF8sDueA9Hjo6woLjgJqV0/yc5vC2HAxUOhx0cWTY" +
            "GcRBgL/yOyQLKiY5TKBH951OjQ4vhF2HmcoO7DkcNLYJOge16ssx4ogBHul20VgF" +
            "XJJjMIIDAzCCAeugAwIBAgIBAjANBgkqhkiG9w0BAQUFADAbMRkwFwYDVQQDExBl" +
            "c3RFeGFtcGxlQ0EgTndOMB4XDTEzMDUwOTAzNTMzMloXDTE0MDUwOTAzNTMzMlow" +
            "GzEZMBcGA1UEAxMQZXN0RXhhbXBsZUNBIE93TjCCASIwDQYJKoZIhvcNAQEBBQAD" +
            "ggEPADCCAQoCggEBAMA6qYh6KWiArm6Uam6RDey6kyKlhCxSAPagw4XhyCrsjh1v" +
            "2QD+0ZeEuWVOoGi1v5LLHgVMXZqMdyjcr7co3oSKH07tvHmVoYMuvywhBlkdzyvn" +
            "4DwQNJdCXyUf/KHl2Wu9KC1UHN4SOJAnqoxTLPm4mB9L6f0ZboX7cmeZM0Mh9RBr" +
            "EZMNf6lCpE2fDwhfFRZWH6plKKrGkU8mW4yCOCfmOv4xBvqe0K3lvc3M+LD3vN3P" +
            "7ocDCzlkJGbSrELYKOQqX2DI7gJpOENo6EKtr3MZXPljSh3/sG6w29dTkWa4pfSE" +
            "pSPeKLpnEc97gRtWIO8/N4XQ32rJnX26fIDkjRUCAwEAAaNSMFAwDgYDVR0PAQH/" +
            "BAQDAgSwMB0GA1UdDgQWBBQITTKxMqATXrfc4ffpCIbt6Gsz0jAfBgNVHSMEGDAW" +
            "gBSxxGnmW6MEp9iXo4s7v7lqsjJCPDANBgkqhkiG9w0BAQUFAAOCAQEALhDaE6Mp" +
            "BINBsJozdbXlijrWxL1CSv8f4GwpUFk3CgZjibt/qW9UoaNR4E58yRopuEhjwFZK" +
            "2w8YtRqx8IZoFhcoLkpBDfgLLwhoztzbYvOVKQMidjBlkBEVNR5MWdrs7F/AxWuy" +
            "iZ2+8AnR8GwqEIbCD0A7xIghmWEMh/BVI9C7GLqd6PxKrTAjuDfEpfdWhU/uYKmK" +
            "cL3XDbSwr30j2EQyaTV/3W0Tn2UfuxdwDQ4ZJs9G+Mw50s7AG6CpISyOIFmX6/bU" +
            "DpJXGLiLwfJ9C/aum9nylYuGCJ68BuTrCs9567KGfXEXI0mdFFCL7TaVR43kjsg3" +
            "c43kZ7369MeEZzCCAvswggHjoAMCAQICCQDprp3DmjOyETANBgkqhkiG9w0BAQUF" +
            "ADAbMRkwFwYDVQQDExBlc3RFeGFtcGxlQ0EgTndOMB4XDTEzMDUwOTAzNTMzMloX" +
            "DTE0MDUwOTAzNTMzMlowGzEZMBcGA1UEAxMQZXN0RXhhbXBsZUNBIE53TjCCASIw" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5962d6zCR8H+zA/SuJrm8RwL7X" +
            "Z67EH+Tn4LTIUSC+GnjzYQHYD8o/ApaMToA91E1fnUNVYjs1cTze2nIpKDp5CHUa" +
            "Y6TqZMjKPipLxzEFxp0E27DAL9alrfUtdgzKaNBjgNXuBnt7neWDzk0f6uj74zed" +
            "SBMGCpLBuwoJcGcAfuSW8IWK9g/9Lm7Rpba4kVYsT1q77fsM/yE6ea3I4f/EUtyx" +
            "PLUMt5EzYSRd2P3rEdrEoDojzYCLaAgE8rG2iDRD6+DHpqjC+LQ6Uf2hvcvvEHu7" +
            "NS8jBbw5XradppgcpAAv+5zmrf6cFJQdLDeduA9VwIM/GSr1q5IfmWjq94cCAwEA" +
            "AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUscRp5lujBKfYl6OLO7+5" +
            "arIyQjwwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQBCz/CWdYvn" +
            "GM/SdCdEiom5A1VxaW8nKgCWg/EyWtAIiaHQuViB+jTUAE9lona2MbJoFHW8U5e8" +
            "9dCP0rJpA9UYXXhWvFQzd5ZWpms4wUYt1j3gqqd36KorJIAuPigVng13yKytxM7c" +
            "VmxQnh0aux3aEnEyRGAhGalHp0RaKdgPRzUaGtipJTNBkSV5S4kD4yDCPHMNbBu+" +
            "OcluerwEpbz6GvE7CpXl2jrTBZSqBsFelq0iz4kk9++9CnwZwrVgdzklhRfJ1Z4j" +
            "NkLruwbQ+o4NvBZsXiKxNfn3K2o3SK8AuaEyDWkq18+5rjcfprRO8x4YTW+6mXPq" +
            "jM0MAGNDEW+1oQAxAA=="
    );

    private static byte[] csrattrs1 = Base64.decode(
        "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJ" +
            "BgcrBgEBAQEWBggqhkjOPQQDAw=="
    );

    private static byte[] csrattrs2 = Base64.decode(
        "   MHwGBysGAQEBARYwIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEG" +
            "   CSqGSIb3DQEJBzAsBgOINwIxJQYDiDcDBgOINwQTGVBhcnNlIFNFVCBhcyAyLjk5" +
            "   OS4yIGRhdGEGCSskAwMCCAEBCwYJYIZIAWUDBAIC"
    );

    public void testParsingCacertsResponse()
        throws Exception
    {
        SimplePKIResponse response = new SimplePKIResponse(cacertsResponse);

        Store<X509CertificateHolder> certs = response.getCertificates();

        assertEquals(4, certs.getMatches(null).size());

        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA OwO"), new BigInteger("11121883874307308188"))).size());
        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA OwO"), new BigInteger("1"))).size());
        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA NwN"), new BigInteger("2"))).size());
        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA NwN"), new BigInteger("16838569520216125969"))).size());
    }

    public void testParsingCsrattrs1()
        throws Exception
    {
        CSRAttributesResponse response = new CSRAttributesResponse(csrattrs1);

        assertTrue(response.hasRequirement(PKCSObjectIdentifiers.pkcs_9_at_challengePassword));
        assertTrue(response.hasRequirement(X9ObjectIdentifiers.ecdsa_with_SHA384));
        assertFalse(response.isAttribute(X9ObjectIdentifiers.ecdsa_with_SHA384));
        assertTrue(response.isAttribute(X9ObjectIdentifiers.id_ecPublicKey));
        assertTrue(response.isAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest));

        Collection<ASN1ObjectIdentifier> requirements = response.getRequirements();

        assertEquals(4, requirements.size());
    }

    public void testParsingCsrattrs2()
        throws Exception
    {
        CSRAttributesResponse response = new CSRAttributesResponse(csrattrs2);

        Collection<ASN1ObjectIdentifier> requirements = response.getRequirements();

        assertEquals(6, requirements.size());

        assertTrue(response.hasRequirement(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.11")));
        assertFalse(response.isAttribute(new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.11")));
        assertTrue(response.hasRequirement(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2")));
        assertFalse(response.isAttribute(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2")));
        assertTrue(response.hasRequirement(new ASN1ObjectIdentifier("1.2.840.113549.1.9.7")));
        assertFalse(response.isAttribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.7")));
        assertTrue(response.hasRequirement(new ASN1ObjectIdentifier("1.3.6.1.1.1.1.22")));
        assertFalse(response.isAttribute(new ASN1ObjectIdentifier("1.3.6.1.1.1.1.22")));
        assertTrue(response.isAttribute(new ASN1ObjectIdentifier("2.999.1")));
        assertTrue(response.isAttribute(new ASN1ObjectIdentifier("2.999.2")));
    }
}
