package org.bouncycastle.cert.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
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
 * draft-ietf-lamps-certdiscovery.
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
        testDescriptorMinimal();
        testDescriptorAllFields();
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

    private void testDescriptorMinimal()
        throws Exception
    {
        RelatedCertificateDescriptor original = new RelatedCertificateDescriptor(
            CertDiscoveryMethod.byLocalPolicy());

        RelatedCertificateDescriptor decoded = RelatedCertificateDescriptor.getInstance(
            original.getEncoded(ASN1Encoding.DER));

        isEquals("method type", CertDiscoveryMethod.byLocalPolicy, decoded.getMethod().getType());
        isTrue("intent absent", decoded.getIntent() == null);
        isTrue("signatureAlgorithm absent", decoded.getSignatureAlgorithm() == null);
        isTrue("publicKeyAlgorithm absent", decoded.getPublicKeyAlgorithm() == null);
    }

    private void testDescriptorAllFields()
        throws Exception
    {
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        AlgorithmIdentifier pkAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);

        RelatedCertificateDescriptor original = new RelatedCertificateDescriptorBuilder()
            .setMethodByUri("https://example.com/companion.cer")
            .setIntent(BCObjectIdentifiers.id_rcd_agility)
            .setSignatureAlgorithm(sigAlg)
            .setPublicKeyAlgorithm(pkAlg)
            .build();

        RelatedCertificateDescriptor decoded = RelatedCertificateDescriptor.getInstance(
            original.getEncoded(ASN1Encoding.DER));

        isEquals("method type", CertDiscoveryMethod.byUri, decoded.getMethod().getType());
        isEquals("uri", "https://example.com/companion.cer", decoded.getMethod().getUri());
        isEquals("intent", BCObjectIdentifiers.id_rcd_agility, decoded.getIntent());
        isEquals("signatureAlgorithm", sigAlg, decoded.getSignatureAlgorithm());
        isEquals("publicKeyAlgorithm", pkAlg, decoded.getPublicKeyAlgorithm());
    }

    private void testFromExtensionsFiltersAndExtracts()
        throws Exception
    {
        AccessDescription ocspAccess = new AccessDescription(
            X509ObjectIdentifiers.id_ad_ocsp,
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com"));

        AccessDescription certDiscovery = new RelatedCertificateDescriptorBuilder()
            .setMethodByUri("https://example.com/dual.cer")
            .setIntent(BCObjectIdentifiers.id_rcd_dual)
            .buildAccessDescription();

        AuthorityInformationAccess sia = new AuthorityInformationAccess(
            new AccessDescription[]{ ocspAccess, certDiscovery });

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectInfoAccess, false, sia);
        Extensions extensions = extGen.generate();

        RelatedCertificateDescriptor[] recovered = RelatedCertificateDescriptor.fromExtensions(extensions);

        isEquals("descriptor count", 1, recovered.length);
        isEquals("recovered intent", BCObjectIdentifiers.id_rcd_dual, recovered[0].getIntent());
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
