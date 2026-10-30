package org.bouncycastle.cert.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CertDiscoveryMethod;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.asn1.x509.RelatedCertificate;
import org.bouncycastle.asn1.x509.RelatedCertificateDescriptor;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.RelatedCertificateDescriptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Round-trip tests for {@link CertDiscoveryMethod},
 * {@link RelatedCertificateDescriptor} and
 * {@link RelatedCertificateDescriptorBuilder} per
 * draft-ietf-lamps-certdiscovery-04.
 */
public class RelatedCertificateDescriptorTest
    extends SimpleTest
{
    private static final byte[] sampleCert = Base64.decode(
        "MIIBuTCCASICAQEwDQYJKoZIhvcNAQEFBQAwJTEWMBQGA1UECgwNQm91bmN5IENhc3R" +
        "sZTELMAkGA1UEBhMCQVUwHhcNMTUwNzIxMjIwNzI3WhcNMTUxMDI5MjIwNzI3WjAlMR" +
        "YwFAYDVQQKDA1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTCBnzANBgkqhkiG9w0BA" +
        "QEFAAOBjQAwgYkCgYEA9MhYrfDoC69iS/56gdvuwOvXKMsx9dSBZnK9KOnCFtc3fTeV" +
        "p+61CeExuKXafqz0ZK/5ps0D+RMCOcIZXtXZsdC3CwgVx3k/CHKgrnp51v8sbgFzRrG" +
        "r68Mp9Dr01wdgxjDCGgToUiBybU8IhsUc2nmwn3+Y+ZoIOvyQDuh3hXUCAwEAATANBg" +
        "kqhkiG9w0BAQUFAAOBgQDvpEa3KFe7b+y7/MPNloabj6lfwW4vdKk4bg9+yMHFsb62O" +
        "B8/RP4sJ+XIB91cGYINgA4d511juc9t6t7kEp6GijqWwAUtQfbyhZIO8DsCl96y3RfU" +
        "ag1L7Q3pn0SfyW0NAI8O9eKG/Hl6WmxRlvx3zmKz1bU+VSlnZoYt+6qZyg==");

    public String getName()
    {
        return "RelatedCertificateDescriptor";
    }

    public void performTest()
        throws Exception
    {
        testMethodByUriRoundTrip();
        testMethodByInclusionRoundTrip();
        testMethodByLocalPolicyRoundTrip();
        testMethodByOtherRoundTrip();
        testMethodRejectsUnknownTag();
        testDescriptorMinimal();
        testDescriptorAllFields();
        testDescriptorExplicitTagging();
        testFromExtensionsFiltersAndExtracts();
        testFromExtensionsAbsent();
    }

    private void testMethodByUriRoundTrip()
        throws Exception
    {
        String uri = "https://example.com/related.cer";
        CertDiscoveryMethod original = CertDiscoveryMethod.byUri(uri);

        CertDiscoveryMethod decoded = CertDiscoveryMethod.getInstance(
            CertDiscoveryMethod.getInstance(original.getEncoded(ASN1Encoding.DER)));

        isEquals("byUri type", CertDiscoveryMethod.byUri, decoded.getType());
        isEquals("byUri URI", uri, decoded.getUri());
        isTrue("byUri certificate must be null", decoded.getCertificate() == null);
        isTrue("byUri is an untagged IA5String", original.toASN1Primitive() instanceof org.bouncycastle.asn1.ASN1IA5String);
    }

    private void testMethodByInclusionRoundTrip()
        throws Exception
    {
        Certificate cert = Certificate.getInstance(sampleCert);
        CertDiscoveryMethod original = CertDiscoveryMethod.byInclusion(cert);

        CertDiscoveryMethod decoded = CertDiscoveryMethod.getInstance(original.getEncoded(ASN1Encoding.DER));

        isEquals("byInclusion type", CertDiscoveryMethod.byInclusion, decoded.getType());
        isTrue("byInclusion URI must be null", decoded.getUri() == null);
        isTrue("byInclusion embedded cert bytes match",
            Arrays.areEqual(cert.getEncoded(ASN1Encoding.DER), decoded.getCertificate().getEncoded(ASN1Encoding.DER)));
    }

    private void testMethodByLocalPolicyRoundTrip()
        throws Exception
    {
        CertDiscoveryMethod original = CertDiscoveryMethod.byLocalPolicy();

        CertDiscoveryMethod decoded = CertDiscoveryMethod.getInstance(original.getEncoded(ASN1Encoding.DER));

        isEquals("byLocalPolicy type", CertDiscoveryMethod.byLocalPolicy, decoded.getType());
        isTrue("byLocalPolicy URI must be null", decoded.getUri() == null);
        isTrue("byLocalPolicy certificate must be null", decoded.getCertificate() == null);
    }

    private void testMethodByOtherRoundTrip()
        throws Exception
    {
        ASN1ObjectIdentifier methodType = new ASN1ObjectIdentifier("1.3.6.1.4.1.22554.99.1");
        DERUTF8String methodValue = new DERUTF8String("ldap://directory.example.com");
        CertDiscoveryMethod original = CertDiscoveryMethod.byOther(methodType, methodValue);

        CertDiscoveryMethod decoded = CertDiscoveryMethod.getInstance(original.getEncoded(ASN1Encoding.DER));

        isEquals("byOther type", CertDiscoveryMethod.byOther, decoded.getType());
        isEquals("byOther method type", methodType, decoded.getOtherMethodType());
        isEquals("byOther method value", methodValue, decoded.getOtherMethodValue());
        isTrue("byOther URI must be null", decoded.getUri() == null);
        isTrue("byOther certificate must be null", decoded.getCertificate() == null);
        isTrue("byUri other type must be null", CertDiscoveryMethod.byUri("x").getOtherMethodType() == null);

        // Wire shape: [0] EXPLICIT SEQUENCE { type-id, [0] EXPLICIT value }.
        ASN1TaggedObject outer = ASN1TaggedObject.getInstance(original.toASN1Primitive());
        isTrue("byOther is context [0]", outer.hasContextTag(0));
        isTrue("byOther [0] is explicit", outer.isExplicit());
        ASN1Sequence inner = ASN1Sequence.getInstance(outer.getExplicitBaseObject());
        isEquals("byOther inner size", 2, inner.size());
        isEquals("byOther inner type-id", methodType, inner.getObjectAt(0));
        ASN1TaggedObject valueTag = ASN1TaggedObject.getInstance(inner.getObjectAt(1));
        isTrue("byOther value is explicit [0]", valueTag.hasContextTag(0) && valueTag.isExplicit());
    }

    private void testMethodRejectsUnknownTag()
        throws Exception
    {
        try
        {
            CertDiscoveryMethod.getInstance(new org.bouncycastle.asn1.DERTaggedObject(true, 1, new DERUTF8String("x")));
            fail("unknown tag accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("unknown tag in CertDiscoveryMethod: 1", e.getMessage());
        }
    }

    private void testDescriptorMinimal()
        throws Exception
    {
        RelatedCertificateDescriptor original = new RelatedCertificateDescriptor(
            CertDiscoveryMethod.byLocalPolicy());

        RelatedCertificateDescriptor decoded = RelatedCertificateDescriptor.getInstance(
            original.getEncoded(ASN1Encoding.DER));

        isEquals("method type", CertDiscoveryMethod.byLocalPolicy, decoded.getMethod().getType());
        isTrue("signatureAlgorithm absent", decoded.getSignatureAlgorithm() == null);
        isTrue("publicKeyAlgorithm absent", decoded.getPublicKeyAlgorithm() == null);
        isTrue("certHash absent", decoded.getCertHash() == null);
    }

    private void testDescriptorAllFields()
        throws Exception
    {
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        AlgorithmIdentifier pkAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
        RelatedCertificate certHash = new RelatedCertificate(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), new DEROctetString(new byte[32]));

        RelatedCertificateDescriptor original = new RelatedCertificateDescriptorBuilder()
            .setMethodByUri("https://example.com/companion.cer")
            .setSignatureAlgorithm(sigAlg)
            .setPublicKeyAlgorithm(pkAlg)
            .setCertHash(certHash)
            .build();

        RelatedCertificateDescriptor decoded = RelatedCertificateDescriptor.getInstance(
            original.getEncoded(ASN1Encoding.DER));

        isEquals("method type", CertDiscoveryMethod.byUri, decoded.getMethod().getType());
        isEquals("uri", "https://example.com/companion.cer", decoded.getMethod().getUri());
        isEquals("signatureAlgorithm", sigAlg, decoded.getSignatureAlgorithm());
        isEquals("publicKeyAlgorithm", pkAlg, decoded.getPublicKeyAlgorithm());
        isEquals("certHash", certHash, decoded.getCertHash());
        isTrue("re-encoding is stable", Arrays.areEqual(original.getEncoded(ASN1Encoding.DER), decoded.getEncoded(ASN1Encoding.DER)));
    }

    private void testDescriptorExplicitTagging()
        throws Exception
    {
        // The module is EXPLICIT TAGS: each optional field must be an explicit
        // context tag wrapping the full AlgorithmIdentifier / RelatedCertificate SEQUENCE.
        RelatedCertificateDescriptor desc = new RelatedCertificateDescriptor(
            CertDiscoveryMethod.byUri("https://example.com/c.cer"),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            new RelatedCertificate(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), new DEROctetString(new byte[32])));

        ASN1Sequence seq = ASN1Sequence.getInstance(desc.getEncoded(ASN1Encoding.DER));
        isEquals("element count", 4, seq.size());
        for (int i = 1; i != 4; i++)
        {
            ASN1TaggedObject tag = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            isTrue("field " + i + " is context [" + (i - 1) + "]", tag.hasContextTag(i - 1));
            isTrue("field " + i + " is explicit", tag.isExplicit());
            isTrue("field " + i + " wraps a SEQUENCE", tag.getExplicitBaseObject() instanceof ASN1Sequence);
        }

        // An implicitly tagged AlgorithmIdentifier (the pre -04 BC encoding) is no longer accepted.
        try
        {
            RelatedCertificateDescriptor.getInstance(new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                CertDiscoveryMethod.byUri("https://example.com/c.cer"),
                new org.bouncycastle.asn1.DERTaggedObject(false, 0, new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption)) }));
            fail("implicit tag accepted");
        }
        catch (RuntimeException e)
        {
            // the ASN.1 layer reports the tag-mode mismatch as an IllegalStateException
            isTrue("unexpected exception: " + e, e instanceof IllegalStateException || e instanceof IllegalArgumentException);
        }
    }

    private void testFromExtensionsFiltersAndExtracts()
        throws Exception
    {
        AccessDescription ocspAccess = new AccessDescription(
            X509ObjectIdentifiers.id_ad_ocsp,
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com"));

        AccessDescription certDiscovery = new RelatedCertificateDescriptorBuilder()
            .setMethodByUri("https://example.com/dual.cer")
            .buildAccessDescription();

        AuthorityInformationAccess sia = new AuthorityInformationAccess(
            new AccessDescription[]{ ocspAccess, certDiscovery });

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectInfoAccess, false, sia);
        Extensions extensions = extGen.generate();

        RelatedCertificateDescriptor[] recovered = RelatedCertificateDescriptor.fromExtensions(extensions);

        isEquals("descriptor count", 1, recovered.length);
        isEquals("recovered URI", "https://example.com/dual.cer", recovered[0].getMethod().getUri());

        // The unrelated OCSP entry must still be present untouched.
        AuthorityInformationAccess sia2 = AuthorityInformationAccess.getInstance(
            ASN1Sequence.getInstance(extensions.getExtension(Extension.subjectInfoAccess).getParsedValue()));
        isEquals("SIA still has 2 entries", 2, sia2.getAccessDescriptions().length);

        // And the wrapping shape is exactly what the draft prescribes:
        // accessLocation must be a GeneralName whose chosen alternative is
        // otherName, and the OtherName.typeID must be the certDiscovery OID.
        AccessDescription discoveryAd = null;
        AccessDescription[] all = sia2.getAccessDescriptions();
        for (int i = 0; i != all.length; i++)
        {
            if (BCObjectIdentifiers.id_ad_certDiscovery.equals(all[i].getAccessMethod()))
            {
                discoveryAd = all[i];
                break;
            }
        }
        isTrue("discovery AccessDescription found", discoveryAd != null);
        isEquals("accessLocation tag is otherName",
            GeneralName.otherName, discoveryAd.getAccessLocation().getTagNo());
        OtherName otherName = OtherName.getInstance(discoveryAd.getAccessLocation().getName());
        isEquals("otherName typeID",
            BCObjectIdentifiers.id_on_relatedCertificateDescriptor, otherName.getTypeID());
    }

    private void testFromExtensionsAbsent()
        throws Exception
    {
        // Extensions present but no SIA: must yield zero.
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true,
            new org.bouncycastle.asn1.x509.BasicConstraints(false));
        Extensions noSia = extGen.generate();

        isEquals("no SIA yields zero descriptors", 0,
            RelatedCertificateDescriptor.fromExtensions(noSia).length);
        isEquals("null extensions yield zero descriptors", 0,
            RelatedCertificateDescriptor.fromExtensions((Extensions)null).length);
    }

    public static void main(String[] args)
    {
        runTest(new RelatedCertificateDescriptorTest());
    }
}
