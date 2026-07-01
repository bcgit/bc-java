package org.bouncycastle.asn1.dvcs.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.dvcs.DVCSRequestInformation;
import org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
import org.bouncycastle.asn1.dvcs.ServiceType;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.Arrays;

/**
 * Regression coverage for the RFC 3029 {@code DVCSRequestInformationBuilder}
 * "seed from an existing request" constructor
 * ({@code DVCSRequestInformationBuilder(DVCSRequestInformation)}), which used to
 * drop the {@code requester} ([0] GeneralNames) and {@code extensions}
 * ([4] Extensions) fields when rebuilding a parsed request.
 */
public class DVCSTest
    extends TestCase
{
    public void testDVCSRequestInformationSeedPreservesRequesterAndExtensions()
        throws Exception
    {
        // RFC 3029 9.1: a DVCS may seed a builder from a received request and re-issue it.
        // The seeded constructor must carry 'requester' ([0] GeneralNames) and 'extensions'
        // ([4] Extensions) forward, otherwise the re-issued request silently loses the
        // original requester identity and all extensions.
        DVCSRequestInformationBuilder b = new DVCSRequestInformationBuilder(ServiceType.VPKC);
        b.setRequester(new GeneralName(GeneralName.dNSName, "requester.example.com"));
        b.setExtensions(new Extensions(new Extension(
            new ASN1ObjectIdentifier("1.2.3.4.12"), false, new DEROctetString(new byte[]{ 4, 2 }))));
        DVCSRequestInformation original = b.build();

        assertNotNull(original.getRequester());
        assertNotNull(original.getExtensions());

        // Parse the encoded request, then re-seed a fresh builder from the parsed object and rebuild.
        DVCSRequestInformation parsed = DVCSRequestInformation.getInstance(p(original));
        DVCSRequestInformation rebuilt = new DVCSRequestInformationBuilder(parsed).build();

        // The rebuilt request must be DER-identical to the original (fails before the seed-constructor fix).
        rt(original, rebuilt);
        assertNotNull(rebuilt.getRequester());
        assertNotNull(rebuilt.getExtensions());
    }

    // ------------------------------------------------------------------

    private static ASN1Primitive p(ASN1Object o)
        throws IOException
    {
        return ASN1Primitive.fromByteArray(o.getEncoded(ASN1Encoding.DER));
    }

    private static void rt(ASN1Object original, ASN1Object decoded)
        throws IOException
    {
        assertTrue("DER round-trip mismatch for " + original.getClass().getSimpleName(),
            Arrays.areEqual(original.getEncoded(ASN1Encoding.DER), decoded.getEncoded(ASN1Encoding.DER)));
    }
}
