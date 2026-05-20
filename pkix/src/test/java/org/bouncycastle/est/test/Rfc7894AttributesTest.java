package org.bouncycastle.est.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.est.AttrOrOID;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.asn1.est.EstIdentityLinking;
import org.bouncycastle.asn1.est.OtpChallenge;
import org.bouncycastle.asn1.est.RevocationChallenge;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.est.CSRAttributesResponse;
import org.bouncycastle.est.TlsUniqueAttributeUtil;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

/**
 * Tests for the RFC 7894 EST CSR-challenge attributes:
 * {@link OtpChallenge}, {@link RevocationChallenge}, {@link EstIdentityLinking}.
 */
public class Rfc7894AttributesTest
    extends TestCase
{
    public void testOtpChallengeRoundTrip()
        throws Exception
    {
        OtpChallenge otp = new OtpChallenge("123456");

        assertEquals("123456", otp.getString());
        assertEquals(PKCSObjectIdentifiers.id_aa_otpChallenge, otp.toAttribute().getAttrType());

        // PrintableString-preferring path: "123456" is in the printable subset
        ASN1Primitive prim = otp.toASN1Primitive();
        assertTrue("expected PrintableString encoding for printable input, got " + prim.getClass(),
            prim instanceof DERPrintableString);

        // Round-trip via Attribute wrapping
        Attribute attr = otp.toAttribute();
        OtpChallenge decoded = OtpChallenge.fromAttribute(attr);
        assertEquals(otp.getString(), decoded.getString());

        // Round-trip via raw getInstance(DirectoryString)
        OtpChallenge fromValue = OtpChallenge.getInstance(otp.getValue());
        assertEquals(otp.getString(), fromValue.getString());

        // Wire-level round-trip through DER encoding
        byte[] enc = otp.getEncoded(ASN1Encoding.DER);
        OtpChallenge reparsed = OtpChallenge.getInstance(ASN1Primitive.fromByteArray(enc));
        assertEquals(otp.getString(), reparsed.getString());
    }

    public void testRevocationChallengeRoundTrip()
        throws Exception
    {
        RevocationChallenge rc = new RevocationChallenge("revoke-me-2026");

        assertEquals("revoke-me-2026", rc.getString());
        assertEquals(PKCSObjectIdentifiers.id_aa_revocationChallenge, rc.toAttribute().getAttrType());

        Attribute attr = rc.toAttribute();
        RevocationChallenge decoded = RevocationChallenge.fromAttribute(attr);
        assertEquals(rc.getString(), decoded.getString());
    }

    public void testEstIdentityLinkingRoundTrip()
        throws Exception
    {
        EstIdentityLinking il = new EstIdentityLinking("tls-unique-base64==");

        assertEquals("tls-unique-base64==", il.getString());
        assertEquals(PKCSObjectIdentifiers.id_aa_estIdentityLinking, il.toAttribute().getAttrType());

        Attribute attr = il.toAttribute();
        EstIdentityLinking decoded = EstIdentityLinking.fromAttribute(attr);
        assertEquals(il.getString(), decoded.getString());
    }

    /**
     * RFC 7894 §3 says values SHOULD use PrintableString when possible. Input
     * containing a character outside the PrintableString subset must fall back
     * to UTF8String.
     */
    public void testUtf8FallbackForNonPrintableInput()
        throws Exception
    {
        // The German umlaut and the at-sign are both outside the
        // PrintableString character set.
        OtpChallenge otp = new OtpChallenge("töken@example");
        ASN1Primitive prim = otp.toASN1Primitive();
        assertTrue("expected UTF8String encoding for non-printable input, got " + prim.getClass(),
            prim instanceof DERUTF8String);
        assertEquals("töken@example", otp.getString());
    }

    /**
     * RFC 7894 §3 caps the value length at 255 characters.
     */
    public void testLengthValidation()
    {
        // Maximum permitted length (255) — must succeed.
        char[] maxBuf = new char[255];
        for (int i = 0; i != maxBuf.length; i++)
        {
            maxBuf[i] = 'a';
        }
        new OtpChallenge(new String(maxBuf));

        // One over the maximum — must reject.
        char[] tooLong = new char[256];
        for (int i = 0; i != tooLong.length; i++)
        {
            tooLong[i] = 'a';
        }
        try
        {
            new OtpChallenge(new String(tooLong));
            fail("expected IllegalArgumentException for length > 255");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("255"));
        }

        // Empty string — must reject.
        try
        {
            new RevocationChallenge("");
            fail("expected IllegalArgumentException for empty value");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("1.."));
        }
    }

    /**
     * fromAttribute should reject an Attribute whose attrType is not the OID
     * the type-specific class expects.
     */
    public void testFromAttributeRejectsWrongOid()
    {
        Attribute revAttr = new RevocationChallenge("foo").toAttribute();
        try
        {
            OtpChallenge.fromAttribute(revAttr);
            fail("expected IllegalArgumentException for wrong attrType");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getMessage(),
                e.getMessage().contains(PKCSObjectIdentifiers.id_aa_otpChallenge.getId()));
        }
    }

    /**
     * The existing {@link CSRAttributesResponse} index machinery should
     * recognise each RFC 7894 attribute via its OID without any per-attribute
     * changes — exercise that explicitly so we don't regress.
     */
    public void testCsrAttributesResponseIndexesNewAttributes()
        throws Exception
    {
        AttrOrOID[] entries = new AttrOrOID[] {
            new AttrOrOID(new OtpChallenge("123456").toAttribute()),
            new AttrOrOID(new RevocationChallenge("revoke-me").toAttribute()),
            new AttrOrOID(new EstIdentityLinking("link-me").toAttribute()),
            new AttrOrOID(PKCSObjectIdentifiers.id_aa_otpChallenge),    // also as a bare OID requirement
        };
        CsrAttrs csrAttrs = new CsrAttrs(entries);
        CSRAttributesResponse resp = new CSRAttributesResponse(csrAttrs);

        assertTrue(resp.hasRequirement(PKCSObjectIdentifiers.id_aa_otpChallenge));
        assertTrue(resp.hasRequirement(PKCSObjectIdentifiers.id_aa_revocationChallenge));
        assertTrue(resp.hasRequirement(PKCSObjectIdentifiers.id_aa_estIdentityLinking));

        // The bare-OID variant should report isAttribute() == false (it's an
        // OID-only requirement); the Attribute-variant entries should report
        // isAttribute() == true. Both supplied an otpChallenge entry — the
        // index keeps the most recently-added value per OID, so we just
        // check the OIDs are all present.
        assertTrue(resp.hasRequirement(PKCSObjectIdentifiers.id_aa_revocationChallenge));
        assertTrue(resp.isAttribute(PKCSObjectIdentifiers.id_aa_revocationChallenge));
        assertTrue(resp.isAttribute(PKCSObjectIdentifiers.id_aa_estIdentityLinking));
    }

    /**
     * Make sure the value classes accept a DirectoryString built from any of
     * the legal {@code DirectoryString} CHOICE branches that callers might
     * pass through {@code getInstance}.
     */
    public void testGetInstanceFromExistingDirectoryString()
        throws Exception
    {
        DirectoryString printable = DirectoryString.getInstance(new DERPrintableString("ABC"));
        OtpChallenge fromPrintable = OtpChallenge.getInstance(printable);
        assertEquals("ABC", fromPrintable.getString());

        DirectoryString utf8 = new DirectoryString("café");
        RevocationChallenge fromUtf8 = RevocationChallenge.getInstance(utf8);
        assertEquals("café", fromUtf8.getString());
    }

    /**
     * RFC 7894 §4: when the server's CSR-Attributes response advertises
     * {@code estIdentityLinking}, {@link TlsUniqueAttributeUtil#setTlsUniqueAttribute}
     * must write the new attribute (and skip the legacy challengePassword).
     */
    public void testTlsUniqueAttributeUtilPicksEstIdentityLinkingWhenAdvertised()
        throws Exception
    {
        byte[] tlsUnique = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
        String expectedB64 = Base64.toBase64String(tlsUnique);

        CSRAttributesResponse advertising = new CSRAttributesResponse(new CsrAttrs(
            new AttrOrOID[] { new AttrOrOID(PKCSObjectIdentifiers.id_aa_estIdentityLinking) }));

        RecordingBuilder builder = newRecordingBuilder();
        TlsUniqueAttributeUtil.setTlsUniqueAttribute(builder, tlsUnique, advertising);

        assertEquals("expected exactly one attribute set", 1, builder.attributes.size());
        Attribute set = builder.attributes.get(0);
        assertEquals(PKCSObjectIdentifiers.id_aa_estIdentityLinking, set.getAttrType());
        assertEquals(expectedB64, EstIdentityLinking.fromAttribute(set).getString());
    }

    /**
     * RFC 7030 §3.5 fallback: when the CSR-Attributes response does not
     * advertise {@code estIdentityLinking}, the legacy {@code challengePassword}
     * attribute is used.
     */
    public void testTlsUniqueAttributeUtilFallsBackToChallengePassword()
        throws Exception
    {
        byte[] tlsUnique = new byte[] { 0x10, 0x20, 0x30, 0x40 };
        String expectedB64 = Base64.toBase64String(tlsUnique);

        // CSR-Attrs advertising only otpChallenge — no estIdentityLinking.
        CSRAttributesResponse otherOnly = new CSRAttributesResponse(new CsrAttrs(
            new AttrOrOID[] { new AttrOrOID(PKCSObjectIdentifiers.id_aa_otpChallenge) }));

        RecordingBuilder builder = newRecordingBuilder();
        TlsUniqueAttributeUtil.setTlsUniqueAttribute(builder, tlsUnique, otherOnly);

        assertEquals(1, builder.attributes.size());
        Attribute set = builder.attributes.get(0);
        assertEquals(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, set.getAttrType());
        assertEquals(1, set.getAttrValues().size());
        assertEquals(expectedB64, ((DERPrintableString)set.getAttrValues().getObjectAt(0)).getString());
    }

    /**
     * A {@code null} CSR-Attributes response also drops through to the legacy
     * challengePassword attribute (the common case for callers that don't
     * fetch CSR attrs at all).
     */
    public void testTlsUniqueAttributeUtilNullCsrAttrsUsesLegacy()
        throws Exception
    {
        byte[] tlsUnique = new byte[] { 0x55, 0x66, 0x77 };

        RecordingBuilder builder = newRecordingBuilder();
        TlsUniqueAttributeUtil.setTlsUniqueAttribute(builder, tlsUnique, null);

        assertEquals(1, builder.attributes.size());
        assertEquals(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
            builder.attributes.get(0).getAttrType());
    }

    // ----- helpers for the TlsUniqueAttributeUtil tests -----

    private static RecordingBuilder newRecordingBuilder()
        throws Exception
    {
        // A minimal SubjectPublicKeyInfo placeholder; the resulting builder is
        // never built / signed, only inspected for which attributes were set.
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            ASN1Primitive.fromByteArray(new byte[] {
                0x30, 0x0c,                                // SEQUENCE
                0x30, 0x07,                                //   SEQUENCE (alg)
                0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,  //   OID sha1
                0x03, 0x01, 0x00                           //   BIT STRING, 0 unused bits, empty
            }));
        return new RecordingBuilder(new X500Name("CN=Test"), spki);
    }

    /**
     * Test double for {@link PKCS10CertificationRequestBuilder} that records
     * which attributes the caller set, without requiring a {@code ContentSigner}
     * or producing a real PKCS#10. Used by the attribute-selection tests above.
     */
    private static class RecordingBuilder
        extends PKCS10CertificationRequestBuilder
    {
        final java.util.List<Attribute> attributes = new java.util.ArrayList<Attribute>();

        RecordingBuilder(X500Name subject, SubjectPublicKeyInfo spki)
        {
            super(subject, spki);
        }

        public PKCS10CertificationRequestBuilder setAttribute(
            org.bouncycastle.asn1.ASN1ObjectIdentifier attrType,
            org.bouncycastle.asn1.ASN1Encodable attrValue)
        {
            attributes.add(new Attribute(attrType, new DERSet(attrValue)));
            return super.setAttribute(attrType, attrValue);
        }
    }

    /**
     * Bare-set / Attribute wrapping shape: an Attribute value built from a
     * DERSet of the DirectoryString should round-trip through Attribute.getInstance
     * and back through fromAttribute.
     */
    public void testWireRoundTripThroughAttribute()
        throws Exception
    {
        OtpChallenge otp = new OtpChallenge("987654");
        Attribute attr = otp.toAttribute();

        byte[] enc = attr.getEncoded(ASN1Encoding.DER);
        Attribute parsed = Attribute.getInstance(ASN1Primitive.fromByteArray(enc));

        assertEquals(PKCSObjectIdentifiers.id_aa_otpChallenge, parsed.getAttrType());
        assertEquals(1, parsed.getAttrValues().size());

        OtpChallenge decoded = OtpChallenge.fromAttribute(parsed);
        assertEquals("987654", decoded.getString());

        // Also: feeding the wire bytes back through Attribute(OID, DERSet(value))
        // directly should produce an equivalent structure.
        Attribute rebuilt = new Attribute(PKCSObjectIdentifiers.id_aa_otpChallenge,
                                          new DERSet(otp.getValue()));
        assertEquals(parsed, rebuilt);
    }
}
