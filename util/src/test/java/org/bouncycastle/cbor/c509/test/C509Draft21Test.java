package org.bouncycastle.cbor.c509.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.c509.C509Attribute;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cbor.c509.C509CertificationRequest;
import org.bouncycastle.cbor.c509.C509CertificationRequestTemplate;
import org.bouncycastle.cbor.c509.C509ConversionOptions;
import org.bouncycastle.cbor.c509.C509Extension;
import org.bouncycastle.cbor.c509.C509ExtensionType;
import org.bouncycastle.cbor.c509.C509Extensions;
import org.bouncycastle.cbor.c509.C509UnregisteredCodes;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tests for the changes draft-ietf-cose-cbor-encoded-cert-21 made to -20, github #2519.
 */
public class C509Draft21Test
    extends TestCase
{
    private static final AlgorithmIdentifier ED25519 = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
    // RFC 8032 sec. 7.1 TEST 1 public key
    private static final SubjectPublicKeyInfo SPKI = new SubjectPublicKeyInfo(ED25519,
        Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    private static final byte[] SIGNATURE = new byte[64];

    // TBSCertificate sequence positions
    private static final int ISSUER = 3;
    private static final int SUBJECT = 6;
    private static final int EXTENSIONS = 9;
    private static final int TBS_ITEMS = 10;

    // C509CertificationRequest array position
    private static final int CR_ATTRIBUTES = 5;

    private static final long BEYOND_INT = 1L << 40;

    private static byte[] nativeTBS(X500Name issuer, X500Name subject, Extensions extensions)
        throws IOException
    {
        return C509Certificate.createTBSCertificate(C509Certificate.TYPE_NATIVE, BigInteger.valueOf(1234), ED25519,
            issuer, new Date(1700000000000L), new Date(1800000000000L), subject, SPKI, extensions,
            C509ConversionOptions.DEFAULT);
    }

    private static byte[][] split(byte[] sequence, int count)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(sequence);
        byte[][] items = new byte[count][];
        for (int i = 0; i != count; i++)
        {
            items[i] = in.readEncodedItem();
        }
        in.expectEnd();
        return items;
    }

    private static byte[][] splitArray(byte[] array)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(array);
        byte[][] items = new byte[in.readArrayHeader()][];
        for (int i = 0; i != items.length; i++)
        {
            items[i] = in.readEncodedItem();
        }
        in.expectEnd();
        return items;
    }

    private static byte[] join(byte[][] items, boolean asArray)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        if (asArray)
        {
            out.writeArrayHeader(items.length);
        }
        for (int i = 0; i != items.length; i++)
        {
            out.writeEncoded(items[i]);
        }
        return bOut.toByteArray();
    }

    private static byte[] integerItem(long value)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeInteger(value);
        return bOut.toByteArray();
    }

    // [ first, second ] with both elements already encoded
    private static byte[] pair(byte[] first, byte[] second)
        throws IOException
    {
        return join(new byte[][]{ first, second }, true);
    }

    private static byte[] textItem(String text)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeTextString(text);
        return bOut.toByteArray();
    }

    private static byte[] byteStringItem(byte[] bytes)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeByteString(bytes);
        return bOut.toByteArray();
    }

    private static byte[] emptyArrayItem()
        throws IOException
    {
        return join(new byte[0][], true);
    }

    private static void expectTBSRejected(byte[][] tbsItems, String message)
        throws IOException
    {
        try
        {
            C509Certificate.create(join(tbsItems, false), SIGNATURE);
            fail("accepted: " + message);
        }
        catch (IOException e)
        {
            assertEquals(message, e.getMessage());
        }
    }

    private static byte[][] baseTBSItems()
        throws IOException
    {
        return split(nativeTBS(new X500Name("CN=issuer"), new X500Name("CN=subject"), null), TBS_ITEMS);
    }

    /*
     * Section 3.1.4: the issuer is null if and only if it is octet-for-octet identical
     * to the subject.
     */
    public void testIssuerNullOnlyWhenOctetIdentical()
        throws Exception
    {
        X500Name subject = new X500Name("CN=test");

        C509Certificate selfIssued = C509Certificate.create(nativeTBS(new X500Name("CN=test"), subject, null),
            SIGNATURE);
        assertTrue(selfIssued.isSelfIssued());

        // X500Name.equals matches these case-insensitively, but the encodings differ
        X500Name issuer = new X500Name("CN=TEST");
        assertEquals(issuer, subject);
        C509Certificate cert = C509Certificate.create(nativeTBS(issuer, subject, null), SIGNATURE);
        assertFalse(cert.isSelfIssued());
        assertTrue(Arrays.areEqual(issuer.getEncoded(ASN1Encoding.DER),
            cert.getIssuer().getEncoded(ASN1Encoding.DER)));
        assertTrue(Arrays.areEqual(subject.getEncoded(ASN1Encoding.DER),
            cert.getSubject().getEncoded(ASN1Encoding.DER)));
        C509Certificate parsed = C509Certificate.getInstance(cert.getEncoded());
        assertTrue(Arrays.areEqual(issuer.getEncoded(ASN1Encoding.DER),
            parsed.getIssuer().getEncoded(ASN1Encoding.DER)));

        // an issuer spelled out although identical to the subject is not the encoding
        byte[][] items = split(nativeTBS(new X500Name("CN=test"), subject, null), TBS_ITEMS);
        items[ISSUER] = items[SUBJECT];
        expectTBSRejected(items, "C509 issuer identical to the subject must be encoded as null");
    }

    /*
     * Section 4.3: the ~oid form of a CR attribute carries the DER-encoded attribute
     * 'values' SET, not a single value.
     */
    public void testGenericCRAttributeCarriesValuesSet()
        throws Exception
    {
        ASN1ObjectIdentifier multi = new ASN1ObjectIdentifier("1.2.3.4");
        ASN1ObjectIdentifier single = new ASN1ObjectIdentifier("1.2.3.5");
        DERSet multiValues = new DERSet(new ASN1Encodable[]{ new DERUTF8String("a"), new DERUTF8String("b") });
        DERSet singleValue = new DERSet(new DERUTF8String("c"));

        CertificationRequest request = request(new DERSet(new ASN1Encodable[]{
            new Attribute(multi, multiValues), new Attribute(single, singleValue) }));
        C509CertificationRequest c509 = C509CertificationRequest.fromCertificationRequest(request,
            C509ConversionOptions.DEFAULT);

        C509Attribute[] attributes = c509.getAttributes();
        assertEquals(2, attributes.length);
        for (int i = 0; i != attributes.length; i++)
        {
            assertNull(attributes[i].getRegistryValue());
            DERSet expected = multi.equals(attributes[i].getAttrType()) ? multiValues : singleValue;
            assertTrue(Arrays.areEqual(byteStringItem(expected.getEncoded(ASN1Encoding.DER)),
                attributes[i].getValueEncoding()));
        }

        // invertible, and the parse of the encoding agrees
        byte[] der = request.getEncoded(ASN1Encoding.DER);
        assertTrue(Arrays.areEqual(der, c509.toCertificationRequest().getEncoded(ASN1Encoding.DER)));
        C509CertificationRequest parsed = C509CertificationRequest.getInstance(c509.getEncoded());
        assertTrue(Arrays.areEqual(der, parsed.toCertificationRequest().getEncoded(ASN1Encoding.DER)));

        // the -20 reading - one bare value in the byte string - is no longer accepted
        byte[][] items = splitArray(c509.getEncoded());
        byte[] oidItem = byteStringItem(Hex.decode("2A0304"));
        items[CR_ATTRIBUTES] = pair(oidItem, byteStringItem(new DERUTF8String("c").getEncoded(ASN1Encoding.DER)));
        expectCRRejected(join(items, true), "malformed C509 CR attribute value");

        items[CR_ATTRIBUTES] = pair(oidItem, byteStringItem(new DERSet().getEncoded(ASN1Encoding.DER)));
        expectCRRejected(join(items, true), "C509 CR attribute values cannot be empty");

        // and an attribute with no values has no C509 form
        try
        {
            C509CertificationRequest.fromCertificationRequest(
                request(new DERSet(new Attribute(single, new DERSet()))), C509ConversionOptions.DEFAULT);
            fail("attribute with no values accepted");
        }
        catch (IOException e)
        {
            assertEquals("certification request attribute with no values cannot be re-encoded as C509",
                e.getMessage());
        }
    }

    private static CertificationRequest request(DERSet attributes)
    {
        CertificationRequestInfo info = new CertificationRequestInfo(new X500Name("CN=subject"), SPKI, attributes);
        return new CertificationRequest(info, ED25519, new DERBitString(SIGNATURE));
    }

    private static void expectCRRejected(byte[] encoding, String message)
    {
        try
        {
            C509CertificationRequest.getInstance(encoding);
            fail("accepted: " + message);
        }
        catch (IOException e)
        {
            assertEquals(message, e.getMessage());
        }
    }

    /*
     * -21 removed Subject Directory Attributes (24) from the C509 Extensions Registry.
     */
    public void testSubjectDirectoryAttributesNotRegistered()
        throws Exception
    {
        assertNull(C509ExtensionType.getOID(24));
        assertNull(C509ExtensionType.getValue(Extension.subjectDirectoryAttributes));

        Vector attributes = new Vector();
        attributes.addElement(new org.bouncycastle.asn1.x509.Attribute(new ASN1ObjectIdentifier("2.5.4.42"),
            new DERSet(new DERUTF8String("Given"))));
        Extensions x509Extensions = new Extensions(new Extension(Extension.subjectDirectoryAttributes, false,
            new SubjectDirectoryAttributes(attributes).getEncoded(ASN1Encoding.DER)));

        // carried in the generic ~oid form, and still exactly
        C509Extensions extensions = C509Extensions.fromX509Extensions(x509Extensions);
        assertNull(extensions.getExtension(0).getRegistryValue());
        assertEquals(x509Extensions, extensions.toX509Extensions());

        C509Certificate cert = C509Certificate.create(
            nativeTBS(new X500Name("CN=issuer"), new X500Name("CN=subject"), x509Extensions), SIGNATURE);
        assertEquals(x509Extensions, C509Certificate.getInstance(cert.getEncoded()).getExtensions()
            .toX509Extensions());

        // the -20 int-coded form now names an unassigned value: a natively signed certificate
        // carries it as an unregistered extension, uninterpreted, and a type 3 cannot carry it
        byte[][] items = baseTBSItems();
        byte[] value = pair(integerItem(42), join(new byte[][]{ textItem("Given") }, true));
        items[EXTENSIONS] = pair(integerItem(24), value);
        C509Extension unregistered = C509Certificate.create(join(items, false), SIGNATURE).getExtensions()
            .getExtension(0);
        assertEquals(C509UnregisteredCodes.extensionID(24), unregistered.getExtnId());
        assertTrue(Arrays.areEqual(value, unregistered.getExtnValue()));
        expectType3Rejected(items, "unknown C509 extension value: 24");
    }

    /*
     * -21 widened the RDN attribute, extension, CR attribute, extended key usage and
     * certificate policy registries to 63 bits. A value with no registry entry has no
     * object identifier: a natively signed structure carries it under a stand-in, and
     * a CBOR re-encoded one, which must reconstruct an X.509 form, cannot carry it.
     */
    public void testRegistryValuesBeyondIntRange()
        throws Exception
    {
        assertNull(C509ExtensionType.getOID(BEYOND_INT));
        assertEquals(Long.valueOf(C509ExtensionType.KEY_USAGE), C509ExtensionType.getValue(Extension.keyUsage));

        byte[][] items = baseTBSItems();

        items[EXTENSIONS] = pair(integerItem(BEYOND_INT), integerItem(1));
        C509Extension extension = parse(items).getExtensions().getExtension(0);
        assertEquals(Long.valueOf(BEYOND_INT), extension.getRegistryValue());
        assertEquals(C509UnregisteredCodes.extensionID(BEYOND_INT), extension.getExtnId());
        assertFalse(extension.isCritical());
        expectType3Rejected(items, "unknown C509 extension value: " + BEYOND_INT);

        items[EXTENSIONS] = pair(integerItem(-BEYOND_INT), integerItem(1));
        extension = parse(items).getExtensions().getExtension(0);
        assertEquals(C509UnregisteredCodes.extensionID(BEYOND_INT), extension.getExtnId());
        assertTrue(extension.isCritical());
        expectType3Rejected(items, "unknown C509 extension value: " + BEYOND_INT);

        // -2^63 is not the critical form of any extension ID in 1 to 2^63 - 1
        items[EXTENSIONS] = pair(integerItem(Long.MIN_VALUE), integerItem(1));
        expectTBSRejected(items, "C509 extensionID out of range: " + Long.MIN_VALUE);

        // nor of a compacted keyUsage
        items[EXTENSIONS] = integerItem(Long.MIN_VALUE);
        expectTBSRejected(items, "C509 keyUsage value out of range: " + Long.MIN_VALUE);

        // extended key usage and certificate policies take the full long range
        long[] codes = { BEYOND_INT, Long.MAX_VALUE, -1, Long.MIN_VALUE };
        for (int i = 0; i != codes.length; i++)
        {
            items[EXTENSIONS] = pair(integerItem(C509ExtensionType.EXTENDED_KEY_USAGE), integerItem(codes[i]));
            ASN1Sequence purposes = ASN1Sequence.getInstance(parse(items).getExtensions().getExtension(0)
                .getExtnValue());
            assertEquals(C509UnregisteredCodes.extendedKeyUsage(codes[i]), purposes.getObjectAt(0));
            assertEquals(codes[i],
                C509UnregisteredCodes.getCode(ASN1ObjectIdentifier.getInstance(purposes.getObjectAt(0))));
            expectType3Rejected(items, "unknown C509 extended key usage value: " + codes[i]);

            items[EXTENSIONS] = pair(integerItem(C509ExtensionType.CERTIFICATE_POLICIES),
                pair(integerItem(codes[i]), emptyArrayItem()));
            PolicyInformation[] policies = CertificatePolicies.getInstance(parse(items).getExtensions()
                .getExtension(0).getExtnValue()).getPolicyInformation();
            assertEquals(C509UnregisteredCodes.certificatePolicy(codes[i]), policies[0].getPolicyIdentifier());
            expectType3Rejected(items, "unknown C509 certificate policy value: " + codes[i]);
        }

        // an RDN attribute: the sign is the string type, as for a registered one
        items = baseTBSItems();
        items[SUBJECT] = pair(integerItem(BEYOND_INT), textItem("x"));
        AttributeTypeAndValue atv = parse(items).getSubject().getRDNs()[0].getFirst();
        assertEquals(C509UnregisteredCodes.rdnAttributeType(BEYOND_INT), atv.getType());
        assertEquals(new DERUTF8String("x"), atv.getValue());
        expectType3Rejected(items, "unknown C509 RDN attribute value: " + BEYOND_INT);

        items[SUBJECT] = pair(integerItem(-BEYOND_INT), textItem("x"));
        atv = parse(items).getSubject().getRDNs()[0].getFirst();
        assertEquals(C509UnregisteredCodes.rdnAttributeType(BEYOND_INT), atv.getType());
        assertEquals(new DERPrintableString("x"), atv.getValue());

        items[SUBJECT] = pair(integerItem(Long.MIN_VALUE), textItem("x"));
        expectTBSRejected(items, "C509 RDN attribute value out of range: " + Long.MIN_VALUE);
        expectType3Rejected(items, "C509 RDN attribute value out of range: " + Long.MIN_VALUE);
    }

    /*
     * A stand-in object identifier has one encoding in a natively signed structure,
     * the int it stands for, and only ever stands for a value the registry lacks.
     */
    public void testUnregisteredCodeStandIns()
        throws Exception
    {
        ASN1ObjectIdentifier attributeType = C509UnregisteredCodes.rdnAttributeType(BEYOND_INT);
        ASN1ObjectIdentifier extensionID = C509UnregisteredCodes.extensionID(BEYOND_INT);
        X500Name subject = new X500Name(new RDN[]{ new RDN(attributeType, new DERUTF8String("x")) });
        Extensions extensions = new Extensions(new Extension[]{
            new Extension(extensionID, true, textItem("opaque")),
            new Extension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(subject)).getEncoded(ASN1Encoding.DER)),
            new Extension(Extension.extendedKeyUsage, false, new DERSequence(new ASN1Encodable[]{
                KeyPurposeId.id_kp_serverAuth.toOID(), C509UnregisteredCodes.extendedKeyUsage(-BEYOND_INT) })
                .getEncoded(ASN1Encoding.DER)),
            new Extension(Extension.certificatePolicies, false, new CertificatePolicies(
                new PolicyInformation(C509UnregisteredCodes.certificatePolicy(BEYOND_INT)))
                .getEncoded(ASN1Encoding.DER)) });

        // built natively, each goes out as its int and comes back as itself
        byte[] tbs = nativeTBS(new X500Name("CN=issuer"), subject, extensions);
        byte[][] items = split(tbs, TBS_ITEMS);
        assertTrue(Arrays.areEqual(pair(integerItem(BEYOND_INT), textItem("x")), items[SUBJECT]));
        byte[][] extensionItems = splitArray(items[EXTENSIONS]);
        assertTrue(Arrays.areEqual(integerItem(-BEYOND_INT), extensionItems[0]));
        assertTrue(Arrays.areEqual(textItem("opaque"), extensionItems[1]));
        // the directoryName inside the subjectAltName too
        assertTrue(Arrays.areEqual(pair(integerItem(4), items[SUBJECT]), extensionItems[3]));
        assertTrue(Arrays.areEqual(pair(integerItem(1), integerItem(-BEYOND_INT)), extensionItems[5]));
        assertTrue(Arrays.areEqual(pair(integerItem(BEYOND_INT), emptyArrayItem()), extensionItems[7]));

        C509Certificate cert = C509Certificate.getInstance(C509Certificate.create(tbs, SIGNATURE).getEncoded());
        assertEquals(subject, cert.getSubject());
        assertEquals(extensions, cert.getExtensions().toX509Extensions());

        // the same content cannot be a type 3 certificate, at any depth
        expectType3Rejected(items, "unknown C509 RDN attribute value: " + BEYOND_INT);
        items[SUBJECT] = textItem("subject");
        items[EXTENSIONS] = join(new byte[][]{ extensionItems[2], extensionItems[3] }, true);
        assertEquals(subject, GeneralNames.getInstance(parse(items).getExtensions().getExtension(0).getExtnValue())
            .getNames()[0].getName());
        expectType3Rejected(items, "unknown C509 RDN attribute value: " + BEYOND_INT);

        // converting from X.509 never writes the int: a stand-in there is just an unknown OID
        assertNull(C509Extensions.fromX509Extensions(extensions).getExtension(0).getRegistryValue());
        byte[] reencoded = C509Certificate.createTBSCertificate(C509Certificate.TYPE_REENCODED_X509,
            BigInteger.valueOf(1234), ED25519, new X500Name("CN=issuer"), new Date(1700000000000L),
            new Date(1800000000000L), subject, SPKI, null, C509ConversionOptions.DEFAULT);
        byte[] genericSubject = pair(byteStringItem(contents(attributeType)),
            byteStringItem(new DERUTF8String("x").getEncoded()));
        assertTrue(Arrays.areEqual(genericSubject, split(reencoded, TBS_ITEMS)[SUBJECT]));
        assertEquals(subject, C509Certificate.create(reencoded, SIGNATURE).getSubject());

        // in the native form the ~oid spelling of a stand-in is refused
        items = baseTBSItems();
        items[SUBJECT] = genericSubject;
        expectTBSRejected(items, "C509 unregistered code identifier " + attributeType + " must be encoded as its int");
        items = baseTBSItems();
        items[EXTENSIONS] = pair(byteStringItem(contents(extensionID)), byteStringItem(new byte[1]));
        expectTBSRejected(items, "C509 unregistered code identifier " + extensionID + " must be encoded as its int");
        items[EXTENSIONS] = pair(integerItem(C509ExtensionType.EXTENDED_KEY_USAGE),
            byteStringItem(contents(C509UnregisteredCodes.extendedKeyUsage(BEYOND_INT))));
        expectTBSRejected(items, "C509 unregistered code identifier "
            + C509UnregisteredCodes.extendedKeyUsage(BEYOND_INT) + " must be encoded as its int");

        // a stand-in never names a registered value
        try
        {
            C509UnregisteredCodes.extensionID(C509ExtensionType.KEY_USAGE);
            fail("stand-in created for a registered extension");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("C509 extension value 2 is registered", e.getMessage());
        }
        try
        {
            C509UnregisteredCodes.rdnAttributeType(-1);
            fail("stand-in created for a negative RDN attribute value");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("C509 RDN attribute value out of range: -1", e.getMessage());
        }
        ASN1ObjectIdentifier forged = BCObjectIdentifiers.bc_c509.branch("2").branch("0").branch("2");
        try
        {
            nativeTBS(new X500Name("CN=issuer"), new X500Name("CN=subject"),
                new Extensions(new Extension(forged, false, integerItem(1))));
            fail("stand-in accepted for a registered extension");
        }
        catch (IOException e)
        {
            assertEquals("C509 unregistered code identifier " + forged
                + " does not name an unregistered extension value", e.getMessage());
        }
        try
        {
            C509UnregisteredCodes.getCode(BCObjectIdentifiers.bc_c509.branch("2").branch("2").branch("5"));
            fail("malformed stand-in accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("malformed C509 unregistered code identifier: "
                + BCObjectIdentifiers.bc_c509.branch("2").branch("2").branch("5"), e.getMessage());
        }

        // an unregistered extension value must be exactly one CBOR item
        try
        {
            nativeTBS(new X500Name("CN=issuer"), new X500Name("CN=subject"),
                new Extensions(new Extension(extensionID, false, new byte[]{ 0x01, 0x02 })));
            fail("accepted two CBOR items as an extension value");
        }
        catch (IOException e)
        {
            assertEquals("unexpected trailing data after CBOR item", e.getMessage());
        }
    }

    private static C509Certificate parse(byte[][] tbsItems)
        throws IOException
    {
        C509Certificate cert = C509Certificate.create(join(tbsItems, false), SIGNATURE);
        // and the full encoding reads back to the same thing
        assertEquals(cert, C509Certificate.getInstance(cert.getEncoded()));
        return cert;
    }

    // the same TBSCertificate marked as a CBOR re-encoded X.509 certificate
    private static void expectType3Rejected(byte[][] tbsItems, String message)
        throws IOException
    {
        byte[][] copy = (byte[][])tbsItems.clone();
        copy[0] = integerItem(C509Certificate.TYPE_REENCODED_X509);
        expectTBSRejected(copy, message);
    }

    // the content octets of an object identifier, the ~oid form
    private static byte[] contents(ASN1ObjectIdentifier oid)
        throws IOException
    {
        byte[] der = oid.getEncoded();
        return Arrays.copyOfRange(der, 2, der.length);
    }

    public void testCRAttributeValueBeyondIntRange()
        throws Exception
    {
        C509CertificationRequest c509 = C509CertificationRequest.fromCertificationRequest(
            request(new DERSet()), C509ConversionOptions.DEFAULT);
        byte[][] items = splitArray(c509.getEncoded());

        items[CR_ATTRIBUTES] = pair(integerItem(BEYOND_INT), integerItem(0));
        expectCRRejected(join(items, true), "unknown C509 CR attribute value: " + BEYOND_INT);

        items[CR_ATTRIBUTES] = pair(integerItem(Long.MIN_VALUE), integerItem(0));
        expectCRRejected(join(items, true), "unknown C509 CR attribute value: " + Long.MIN_VALUE);

        // a natively signed request carries either under a stand-in, the value uninterpreted
        byte[] tbs = C509CertificationRequest.createTBSCertificationRequest(C509CertificationRequest.TYPE_NATIVE,
            ED25519, new X500Name("CN=subject"), SPKI, null, "password", null, C509ConversionOptions.DEFAULT);
        items = splitArray(C509CertificationRequest.create(tbs, SIGNATURE).getEncoded());
        byte[] password = splitArray(items[CR_ATTRIBUTES])[1];
        long[] codes = { BEYOND_INT, Long.MIN_VALUE };
        for (int i = 0; i != codes.length; i++)
        {
            items[CR_ATTRIBUTES] = join(new byte[][]{ integerItem(C509Attribute.CHALLENGE_PASSWORD), password,
                integerItem(codes[i]), integerItem(0) }, true);
            C509CertificationRequest request = C509CertificationRequest.getInstance(join(items, true));
            assertTrue(Arrays.areEqual(join(items, true), request.getEncoded()));
            assertEquals(2, request.getAttributes().length);
            C509Attribute attribute = request.getAttributes()[1];
            assertEquals(Long.valueOf(codes[i]), attribute.getRegistryValue());
            assertEquals(C509UnregisteredCodes.crAttributeType(codes[i]), attribute.getAttrType());
            assertTrue(Arrays.areEqual(integerItem(0), attribute.getValueEncoding()));
        }
        try
        {
            C509UnregisteredCodes.crAttributeType(C509Attribute.CHALLENGE_PASSWORD);
            fail("stand-in created for a registered CR attribute value");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("C509 CR attribute value 1 is registered", e.getMessage());
        }
    }

    public void testTemplateRegistryValues()
        throws Exception
    {
        C509CertificationRequestTemplate.RDNAttributeTemplate attribute =
            new C509CertificationRequestTemplate.RDNAttributeTemplate(BEYOND_INT, 1, 1, null);
        assertEquals(Long.valueOf(BEYOND_INT), attribute.getRegistryValue());

        try
        {
            new C509CertificationRequestTemplate.RDNAttributeTemplate(-1, 1, 1, null);
            fail("negative RDN attribute template value accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("registryValue must be at least 0", e.getMessage());
        }

        try
        {
            new C509CertificationRequestTemplate.ExtensionTemplate(0, false, null);
            fail("extension template value 0 accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("registryValue must be at least 1", e.getMessage());
        }
    }
}
