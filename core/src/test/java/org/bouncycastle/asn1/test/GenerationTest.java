package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class GenerationTest
    extends SimpleTest
{
    private byte[] v1Cert = Base64.decode(
          "MIGtAgEBMA0GCSqGSIb3DQEBBAUAMCUxCzAJBgNVBAMMAkFVMRYwFAYDVQQKDA1Cb"
        + "3VuY3kgQ2FzdGxlMB4XDTcwMDEwMTAwMDAwMVoXDTcwMDEwMTAwMDAxMlowNjELMA"
        + "kGA1UEAwwCQVUxFjAUBgNVBAoMDUJvdW5jeSBDYXN0bGUxDzANBgNVBAsMBlRlc3Q"
        + "gMTAaMA0GCSqGSIb3DQEBAQUAAwkAMAYCAQECAQI=");

    private byte[] v3Cert = Base64.decode(
          "MIIBSKADAgECAgECMA0GCSqGSIb3DQEBBAUAMCUxCzAJBgNVBAMMAkFVMRYwFAYD"
        + "VQQKDA1Cb3VuY3kgQ2FzdGxlMB4XDTcwMDEwMTAwMDAwMVoXDTcwMDEwMTAwMDAw"
        + "MlowNjELMAkGA1UEAwwCQVUxFjAUBgNVBAoMDUJvdW5jeSBDYXN0bGUxDzANBgNV"
        + "BAsMBlRlc3QgMjAYMBAGBisOBwIBATAGAgEBAgECAwQAAgEDo4GVMIGSMGEGA1Ud"
        + "IwEB/wRXMFWAFDZPdpHPzKi7o8EJokkQU2uqCHRRoTqkODA2MQswCQYDVQQDDAJB"
        + "VTEWMBQGA1UECgwNQm91bmN5IENhc3RsZTEPMA0GA1UECwwGVGVzdCAyggECMCAG"
        + "A1UdDgEB/wQWBBQ2T3aRz8you6PBCaJJEFNrqgh0UTALBgNVHQ8EBAMCBBA=");

    private byte[] v3CertNullSubject = Base64.decode(
          "MIHGoAMCAQICAQIwDQYJKoZIhvcNAQEEBQAwJTELMAkGA1UEAwwCQVUxFjAUBgNVB"
        + "AoMDUJvdW5jeSBDYXN0bGUwHhcNNzAwMTAxMDAwMDAxWhcNNzAwMTAxMDAwMDAyWj"
        + "AAMBgwEAYGKw4HAgEBMAYCAQECAQIDBAACAQOjSjBIMEYGA1UdEQEB/wQ8MDqkODA"
        + "2MQswCQYDVQQDDAJBVTEWMBQGA1UECgwNQm91bmN5IENhc3RsZTEPMA0GA1UECwwG"
        + "VGVzdCAy");

    private byte[] v2CertList = Base64.decode(
          "MIIBQwIBATANBgkqhkiG9w0BAQUFADAlMQswCQYDVQQDDAJBVTEWMBQGA1UECgwN" +
          "Qm91bmN5IENhc3RsZRcNNzAwMTAxMDAwMDAwWhcNNzAwMTAxMDAwMDAyWjAiMCAC" +
          "AQEXDTcwMDEwMTAwMDAwMVowDDAKBgNVHRUEAwoBCqCBxTCBwjBhBgNVHSMBAf8E" +
          "VzBVgBQ2T3aRz8you6PBCaJJEFNrqgh0UaE6pDgwNjELMAkGA1UEAwwCQVUxFjAU" +
          "BgNVBAoMDUJvdW5jeSBDYXN0bGUxDzANBgNVBAsMBlRlc3QgMoIBAjBDBgNVHRIE" +
          "PDA6pDgwNjELMAkGA1UEAwwCQVUxFjAUBgNVBAoMDUJvdW5jeSBDYXN0bGUxDzAN" +
          "BgNVBAsMBlRlc3QgMzAKBgNVHRQEAwIBATAMBgNVHRwBAf8EAjAA");
    
    private void tbsV1CertGen()
        throws IOException
    {
        V1TBSCertificateGenerator   gen = new V1TBSCertificateGenerator();
        Date                        startDate = new Date(1000);
        Date                        endDate = new Date(12000);

        gen.setSerialNumber(new ASN1Integer(1));

        gen.setStartDate(new Time(startDate));
        gen.setEndDate(new Time(endDate));

        gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));
        gen.setSubject(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 1"));

        gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption, DERNull.INSTANCE));

        SubjectPublicKeyInfo    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                                                     new RSAPublicKey(BigInteger.valueOf(1), BigInteger.valueOf(2)));

        gen.setSubjectPublicKeyInfo(info);

        TBSCertificate tbs = gen.generateTBSCertificate();

        byte[] encoding = tbs.getEncoded();
        if (!Arrays.areEqual(encoding, v1Cert))
        {
            fail("failed v1 cert generation");
        }

        //
        // read back test
        //
        ASN1Primitive o = ASN1Primitive.fromByteArray(v1Cert);

        encoding = o.getEncoded();
        if (!Arrays.areEqual(encoding, v1Cert))
        {
            fail("failed v1 cert read back test");
        }
    }
    
    private AuthorityKeyIdentifier createAuthorityKeyId(
        SubjectPublicKeyInfo    info,
        X500Name                name,
        int                     sNumber)
    {
        GeneralName             genName = new GeneralName(name);
        ASN1EncodableVector     v = new ASN1EncodableVector();

        v.add(genName);

        return new AuthorityKeyIdentifier(
            info, GeneralNames.getInstance(new DERSequence(v)), BigInteger.valueOf(sNumber));
    }
    
    private void tbsV3CertGen()
        throws IOException
    {
        V3TBSCertificateGenerator   gen = new V3TBSCertificateGenerator();
        Date                        startDate = new Date(1000);
        Date                        endDate = new Date(2000);

        gen.setSerialNumber(new ASN1Integer(2));

        gen.setStartDate(new Time(startDate));
        gen.setEndDate(new Time(endDate));

        gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));
        gen.setSubject(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"));

        gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption, DERNull.INSTANCE));

        SubjectPublicKeyInfo    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(BigInteger.valueOf(1), BigInteger.valueOf(2))), new ASN1Integer(3));

        gen.setSubjectPublicKeyInfo(info);

        //
        // add extensions
        //
        Extensions ex = new Extensions(new Extension[] {
            new Extension(Extension.authorityKeyIdentifier, true, new DEROctetString(createAuthorityKeyId(info, new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"), 2))),
            new Extension(Extension.subjectKeyIdentifier, true, new DEROctetString(new SubjectKeyIdentifier(getDigest(info)))),
            new Extension(Extension.keyUsage, false, new DEROctetString(new KeyUsage(KeyUsage.dataEncipherment)))
        });

        gen.setExtensions(ex);

        TBSCertificate tbs = gen.generateTBSCertificate();

        byte[] encoding = tbs.getEncoded();
        if (!Arrays.areEqual(encoding, v3Cert))
        {
            fail("failed v3 cert generation");
        }

        //
        // read back test
        //
        ASN1Primitive o = ASN1Primitive.fromByteArray(v3Cert);

        encoding = o.getEncoded();
        if (!Arrays.areEqual(encoding, v3Cert))
        {
            fail("failed v3 cert read back test");
        }
    }

    private void tbsV3CertGenWithNullSubject()
        throws IOException
    {
        V3TBSCertificateGenerator   gen = new V3TBSCertificateGenerator();
        Date                        startDate = new Date(1000);
        Date                        endDate = new Date(2000);

        gen.setSerialNumber(new ASN1Integer(2));

        gen.setStartDate(new Time(startDate));
        gen.setEndDate(new Time(endDate));

        gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));

        gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption, DERNull.INSTANCE));

        SubjectPublicKeyInfo    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(BigInteger.valueOf(1), BigInteger.valueOf(2))), new ASN1Integer(3));

        gen.setSubjectPublicKeyInfo(info);

        try
        {
            gen.generateTBSCertificate();
            fail("null subject not caught!");
        }
        catch (IllegalStateException e)
        {
            if (!e.getMessage().equals("not all mandatory fields set in V3 TBScertificate generator"))
            {
                fail("unexpected exception", e);
            }
        }

        //
        // add extensions
        //

        Extensions ex = new Extensions(new Extension(Extension.subjectAlternativeName, true,
            new DEROctetString(new GeneralNames(new GeneralName(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"))))));

        gen.setExtensions(ex);

        TBSCertificate tbs = gen.generateTBSCertificate();

        byte[] encoding = tbs.getEncoded();
        if (!Arrays.areEqual(encoding, v3CertNullSubject))
        {
            fail("failed v3 null sub cert generation");
        }

        //
        // read back test
        //
        ASN1Primitive o = ASN1Primitive.fromByteArray(v3CertNullSubject);

        encoding = o.getEncoded();
        if (!Arrays.areEqual(encoding, v3CertNullSubject))
        {
            fail("failed v3 null sub cert read back test");
        }
    }

    private void tbsV2CertListGen()
        throws IOException
    {
        V2TBSCertListGenerator  gen = new V2TBSCertListGenerator();

        gen.setIssuer(new X500Name("CN=AU,O=Bouncy Castle"));

        gen.addCRLEntry(new ASN1Integer(1), new Time(new Date(1000)), CRLReason.aACompromise);

        gen.setNextUpdate(new Time(new Date(2000)));

        gen.setThisUpdate(new Time(new Date(500)));

        gen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));

        //
        // extensions
        //
        SubjectPublicKeyInfo    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(BigInteger.valueOf(1), BigInteger.valueOf(2))), new ASN1Integer(3));

        ExtensionsGenerator     extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.authorityKeyIdentifier, true, createAuthorityKeyId(info, new X500Name("CN=AU,O=Bouncy Castle,OU=Test 2"), 2));
        extGen.addExtension(Extension.issuerAlternativeName, false, new GeneralNames(new GeneralName(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 3"))));
        extGen.addExtension(Extension.cRLNumber, false, new ASN1Integer(1));
        extGen.addExtension(Extension.issuingDistributionPoint, true, IssuingDistributionPoint.getInstance(new DERSequence()));

        isTrue(extGen.hasExtension(Extension.cRLNumber));
        isTrue(!extGen.hasExtension(Extension.freshestCRL));

        isEquals(new Extension(Extension.cRLNumber, false, new ASN1Integer(1).getEncoded()), extGen.getExtension(Extension.cRLNumber));

        Extensions          ex = extGen.generate();

        gen.setExtensions(ex);

        TBSCertList tbs = gen.generateTBSCertList();

        byte[] encoding = tbs.getEncoded();
        if (!Arrays.areEqual(encoding, v2CertList))
        {
            System.out.println(new String(Base64.encode(encoding)));
            fail("failed v2 cert list generation");
        }

        // extGen - check replacement.
        extGen.replaceExtension(Extension.cRLNumber, false, new ASN1Integer(2));

        isEquals(new Extension(Extension.cRLNumber, false, new ASN1Integer(2).getEncoded()), extGen.getExtension(Extension.cRLNumber));

        // extGen - check remove.
        extGen.removeExtension(Extension.cRLNumber);

        isTrue(!extGen.hasExtension(Extension.cRLNumber));

        // check we can still generate
        ex = extGen.generate();
        
        //
        // read back test
        //
        ASN1Primitive o = ASN1Primitive.fromByteArray(v2CertList);

        encoding = o.getEncoded();
        if (!Arrays.areEqual(encoding, v2CertList))
        {
            fail("failed v2 cert list read back test");
        }

        //
        // check we can add a custom reason
        //
        gen.addCRLEntry(new ASN1Integer(1), new Time(new Date(1000)), CRLReason.aACompromise);

        //
        // check invalidity date
        gen.addCRLEntry(new ASN1Integer(2), new Time(new Date(1000)), CRLReason.affiliationChanged, new ASN1GeneralizedTime(new Date(2000)));

        TBSCertList crl = gen.generateTBSCertList();

        TBSCertList.CRLEntry[] entries = crl.getRevokedCertificates();
        for (int i = 0; i != entries.length; i++)
        {
            TBSCertList.CRLEntry entry = entries[i];

            if (entry.getUserCertificate().equals(new ASN1Integer(1)))
            {
                Extensions extensions = entry.getExtensions();
                Extension ext = extensions.getExtension(Extension.reasonCode);

                CRLReason r = CRLReason.getInstance(ext.getParsedValue());

                if (r.getValue().intValue() != CRLReason.aACompromise)
                {
                    fail("reason code mismatch");
                }
            }
            else if (entry.getUserCertificate().equals(new ASN1Integer(2)))
            {
                Extensions extensions = entry.getExtensions();
                Extension ext = extensions.getExtension(Extension.reasonCode);

                CRLReason r = CRLReason.getInstance(ext.getParsedValue());

                if (r.getValue().intValue() != CRLReason.affiliationChanged)
                {
                    fail("reason code mismatch");
                }

                ext = extensions.getExtension(Extension.invalidityDate);

                ASN1GeneralizedTime t = ASN1GeneralizedTime.getInstance(ext.getParsedValue());

                try
                {
                    if (!t.getDate().equals(new Date(2000)))
                    {
                        fail("invalidity date mismatch");
                    }
                }
                catch (ParseException e)
                {
                    fail("can't parse date", e);
                }
            }
        }
    }
    
    public void performTest()
        throws Exception
    {
        tbsV1CertGen();
        tbsV3CertGen();
        tbsV3CertGenWithNullSubject();
        tbsV2CertListGen();
    }

    public String getName()
    {
        return "Generation";
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

    public static void main(
        String[] args)
    {
        runTest(new GenerationTest());
    }
}
