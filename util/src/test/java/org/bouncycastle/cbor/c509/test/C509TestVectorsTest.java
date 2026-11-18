package org.bouncycastle.cbor.c509.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PrivateKeyPossessionStatement;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.c509.C509Attribute;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cbor.c509.C509CertificationRequest;
import org.bouncycastle.cbor.c509.C509CertificationRequestTemplate;
import org.bouncycastle.cbor.c509.C509ConversionOptions;
import org.bouncycastle.cbor.c509.C509Extension;
import org.bouncycastle.cbor.c509.C509Extensions;
import org.bouncycastle.cbor.c509.C509PrivateKeyPossessionStatement;
import org.bouncycastle.cbor.c509.C509SignatureAlgorithm;
import org.bouncycastle.cbor.c509.C509UnregisteredCodes;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * Tests driven by the vectors of draft-ietf-cose-c509-test-vectors-04, held in
 * bc-test-data under c509/test-vectors (see its README). Every certificate,
 * certification request and template the draft publishes is converted, reconstructed
 * and round-tripped; signature verification is covered on the pkix side.
 * <p>
 * Sections 7, 11 and 12.4 use 8-byte integer codes no registry defines, which exist
 * in the natively signed form only and are read as the stand-in object identifiers of
 * {@link C509UnregisteredCodes}.
 */
public class C509TestVectorsTest
    extends TestCase
{
    private static final C509ConversionOptions UNCOMPRESSED =
        C509ConversionOptions.DEFAULT.withPointCompression(false);

    // certificate vectors publishing all of the X.509, type 3 and type 2 forms
    private static final String[] CERT_TAGS = {
        "2", "3_1", "3_2", "3_3", "3_5", "3_6", "3_7", "3_8", "3_9", "3_10", "3_11", "3_12", "3_13", "3_14", "3_15",
        "4_1", "4_17", "4_18", "4_19", "4_20", "4_21", "4_22" };

    private static byte[] vector(String name)
        throws IOException
    {
        InputStream in = TestResourceFinder.findTestResource("c509/test-vectors", name + ".hex");
        return Hex.decode(Strings.fromByteArray(Streams.readAll(in)).trim());
    }

    private static void checkCertificate(String tag, byte[] der, byte[] t3, byte[] t2, C509ConversionOptions options)
        throws IOException
    {
        // X.509 -> type 3 must match the draft's encoding exactly
        C509Certificate c509 = C509Certificate.fromX509Certificate(Certificate.getInstance(der), options);
        assertTrue(tag + ": type 3 encoding differs", Arrays.areEqual(t3, c509.getEncoded()));

        // type 3 -> X.509 must reproduce the DER byte for byte, and re-encoding is the identity
        C509Certificate parsed = C509Certificate.getInstance(t3);
        assertEquals(tag, C509Certificate.TYPE_REENCODED_X509, parsed.getCertificateType());
        assertTrue(tag + ": reconstructed DER differs",
            Arrays.areEqual(der, parsed.toX509Certificate().getEncoded(ASN1Encoding.DER)));
        assertTrue(tag + ": type 3 re-encoding differs", Arrays.areEqual(t3, parsed.getEncoded()));

        if (t2 != null)
        {
            C509Certificate nativeCert = C509Certificate.getInstance(t2);
            assertEquals(tag, C509Certificate.TYPE_NATIVE, nativeCert.getCertificateType());
            assertTrue(tag + ": type 2 re-encoding differs", Arrays.areEqual(t2, nativeCert.getEncoded()));
            // the two types describe the same certificate
            assertEquals(tag, parsed.getSerialNumber(), nativeCert.getSerialNumber());
            assertEquals(tag, parsed.getIssuer(), nativeCert.getIssuer());
            assertEquals(tag, parsed.getSubject(), nativeCert.getSubject());
            assertEquals(tag, parsed.getNotBefore(), nativeCert.getNotBefore());
            assertEquals(tag, parsed.getNotAfter(), nativeCert.getNotAfter());
            assertEquals(tag, parsed.getExtensions().size(), nativeCert.getExtensions().size());
        }
    }

    public void testCertificateVectors()
        throws Exception
    {
        for (int i = 0; i != CERT_TAGS.length; i++)
        {
            String tag = CERT_TAGS[i];
            checkCertificate(tag, vector(tag + "_x509"), vector(tag + "_t3"), vector(tag + "_t2"), UNCOMPRESSED);
        }

        // Section 3.4 is Section 3.3's certificate with its point compressed
        checkCertificate("3_4", vector("3_3_x509"), vector("3_4_t3"), vector("3_4_t2"),
            C509ConversionOptions.DEFAULT);

        // Section 8 publishes no type 2 form
        checkCertificate("8", vector("8_x509"), vector("8_t3"), null, UNCOMPRESSED);
    }

    // the 8-byte codes of Sections 7, 11 and 12.4
    private static final long CODE = 0x70FFFFFFFFFFFFFFL;

    public void testUnregisteredCodeCertificateVector()
        throws Exception
    {
        byte[] t2 = vector("7_t2");
        C509Certificate cert = C509Certificate.getInstance(t2);
        assertEquals(C509Certificate.TYPE_NATIVE, cert.getCertificateType());
        assertTrue(Arrays.areEqual(t2, cert.getEncoded()));

        // RDN attribute type
        RDN[] rdns = cert.getSubject().getRDNs();
        assertEquals(2, rdns.length);
        assertEquals(C509UnregisteredCodes.rdnAttributeType(CODE), rdns[1].getFirst().getType());
        assertEquals(new DERUTF8String("my 8-byte attribute"), rdns[1].getFirst().getValue());

        C509Extensions extensions = cert.getExtensions();
        assertEquals(5, extensions.size());

        // certificate policy identifiers, positive and negative
        PolicyInformation[] policies = CertificatePolicies.getInstance(
            extensions.getExtension(1).getExtnValue()).getPolicyInformation();
        assertEquals(2, policies.length);
        assertEquals(C509UnregisteredCodes.certificatePolicy(0x70FFFFFFFFFFFFF0L), policies[0].getPolicyIdentifier());
        assertEquals(C509UnregisteredCodes.certificatePolicy(-0x70FFFFFFFFFFFFF1L), policies[1].getPolicyIdentifier());

        // extended key usages, positive and negative
        ASN1Sequence purposes = ASN1Sequence.getInstance(extensions.getExtension(2).getExtnValue());
        assertEquals(2, purposes.size());
        assertEquals(C509UnregisteredCodes.extendedKeyUsage(0x70FFFFFFFFFFFFF2L), purposes.getObjectAt(0));
        assertEquals(C509UnregisteredCodes.extendedKeyUsage(-0x70FFFFFFFFFFFFF3L), purposes.getObjectAt(1));

        // extension IDs, critical and not: the value is the CBOR item as it stands
        C509Extension critical = extensions.getExtension(3);
        assertEquals(Long.valueOf(0x70FFFFFFFFFFFFFEL), critical.getRegistryValue());
        assertEquals(C509UnregisteredCodes.extensionID(0x70FFFFFFFFFFFFFEL), critical.getExtnId());
        assertTrue(critical.isCritical());
        assertEquals("my critical example", new CBORDecoder(critical.getExtnValue()).readTextString());

        C509Extension nonCritical = extensions.getExtension(4);
        assertEquals(C509UnregisteredCodes.extensionID(CODE), nonCritical.getExtnId());
        assertFalse(nonCritical.isCritical());
        assertEquals("my non-critical example", new CBORDecoder(nonCritical.getExtnValue()).readTextString());

        // the stand-ins give the codes back
        assertTrue(C509UnregisteredCodes.isUnregisteredCode(nonCritical.getExtnId()));
        assertEquals(CODE, C509UnregisteredCodes.getCode(nonCritical.getExtnId()));
        assertEquals(-0x70FFFFFFFFFFFFF3L,
            C509UnregisteredCodes.getCode(ASN1ObjectIdentifier.getInstance(purposes.getObjectAt(1))));
        assertFalse(C509UnregisteredCodes.isUnregisteredCode(rdns[0].getFirst().getType()));

        // and the certificate rebuilds from its X.509 style parts
        byte[] tbs = C509Certificate.createTBSCertificate(C509Certificate.TYPE_NATIVE, cert.getSerialNumber(),
            cert.getIssuerSignatureAlgorithm().toX509AlgorithmIdentifier(), cert.getIssuer(),
            C509Certificate.toDate(cert.getNotBefore()), C509Certificate.toDate(cert.getNotAfter()),
            cert.getSubject(), cert.getSubjectPublicKeyInfo(), extensions.toX509Extensions(), UNCOMPRESSED);
        assertTrue(Arrays.areEqual(cert.getTBSCertificateEncoded(), tbs));
        assertTrue(Arrays.areEqual(t2, C509Certificate.create(tbs, cert.getSignature(), UNCOMPRESSED).getEncoded()));

        // there is no X.509 form, so the same content marked as type 3 is refused
        byte[] t3 = Arrays.clone(t2);
        t3[1] = C509Certificate.TYPE_REENCODED_X509;
        try
        {
            C509Certificate.getInstance(t3);
            fail("accepted an unregistered code in a type 3 certificate");
        }
        catch (IOException e)
        {
            assertEquals("unknown C509 RDN attribute value: " + CODE, e.getMessage());
        }
    }

    public void testUnregisteredCodeRequestVector()
        throws Exception
    {
        byte[] t2 = vector("11_t2");
        C509CertificationRequest request = C509CertificationRequest.getInstance(t2);
        assertEquals(C509CertificationRequest.TYPE_NATIVE, request.getRequestType());
        assertTrue(Arrays.areEqual(t2, request.getEncoded()));

        long code = 0x0070FFFFFFFFFFFFL;
        assertEquals(1, request.getAttributes().length);
        C509Attribute attribute = request.getAttributes()[0];
        assertEquals(Long.valueOf(code), attribute.getRegistryValue());
        assertEquals(C509UnregisteredCodes.crAttributeType(code), attribute.getAttrType());
        assertEquals("my 8-byte example", new CBORDecoder(attribute.getValueEncoding()).readTextString());

        // there is no RFC 2986 form, so the same content marked as type 3 is refused
        byte[] t3 = Arrays.clone(t2);
        t3[1] = C509CertificationRequest.TYPE_REENCODED_PKCS10;
        checkRejected(t3, "unknown C509 CR attribute value: " + code);
    }

    public void testUnregisteredCodeTemplateVector()
        throws Exception
    {
        C509CertificationRequestTemplate template = C509CertificationRequestTemplate.getInstance(
            vector("12_4_template"));
        C509CertificationRequestTemplate.RDNAttributeTemplate[] subject = template.getSubjectTemplate();
        assertEquals(2, subject.length);
        assertEquals(Long.valueOf(CODE), subject[1].getRegistryValue());
        C509CertificationRequestTemplate.ExtensionTemplate[] extensions = template.getExtensionsTemplate();
        assertEquals(2, extensions.length);
        assertEquals(Long.valueOf(CODE), extensions[1].getRegistryValue());
    }

    private static void checkCertificationRequest(String tag, byte[] der, byte[] t3, byte[] t2)
        throws IOException
    {
        C509CertificationRequest c509 = C509CertificationRequest.fromCertificationRequest(
            CertificationRequest.getInstance(der), UNCOMPRESSED);
        assertTrue(tag + ": type 3 encoding differs", Arrays.areEqual(t3, c509.getEncoded()));

        C509CertificationRequest parsed = C509CertificationRequest.getInstance(t3);
        assertEquals(tag, C509CertificationRequest.TYPE_REENCODED_PKCS10, parsed.getRequestType());
        assertTrue(tag + ": reconstructed DER differs",
            Arrays.areEqual(der, parsed.toCertificationRequest().getEncoded(ASN1Encoding.DER)));
        assertTrue(tag + ": type 3 re-encoding differs", Arrays.areEqual(t3, parsed.getEncoded()));

        if (t2 != null)
        {
            C509CertificationRequest nativeRequest = C509CertificationRequest.getInstance(t2);
            assertEquals(tag, C509CertificationRequest.TYPE_NATIVE, nativeRequest.getRequestType());
            assertTrue(tag + ": type 2 re-encoding differs", Arrays.areEqual(t2, nativeRequest.getEncoded()));
            assertEquals(tag, parsed.getSubject(), nativeRequest.getSubject());
            assertEquals(tag, parsed.getAttributes().length, nativeRequest.getAttributes().length);
        }
    }

    public void testCertificationRequestVectors()
        throws Exception
    {
        for (int i = 1; i <= 7; i++)
        {
            String tag = "9_" + i;
            // Section 9.2 publishes no type 2 form
            checkCertificationRequest(tag, vector(tag + "_pkcs10"), vector(tag + "_t3"),
                i == 2 ? null : vector(tag + "_t2"));
        }
    }

    public void testDhSigStaticVectors()
        throws Exception
    {
        // Sections 9.3 and 9.5: the bare hashValue stands for a DhSigStatic without issuerAndSerial
        C509CertificationRequest sha256 = C509CertificationRequest.getInstance(vector("9_3_t2"));
        assertEquals(Integer.valueOf(C509SignatureAlgorithm.ECDH_POP_SHA256_HMAC_SHA256),
            sha256.getSubjectSignatureAlgorithm().getRegistryValue());
        DhSigStatic dhSig = DhSigStatic.getInstance(sha256.getSignature());
        assertNull(dhSig.getIssuerAndSerial());
        assertEquals(32, dhSig.getHashValue().length);

        // Section 9.4: the array form carries the issuer and serial number
        C509CertificationRequest sha384 = C509CertificationRequest.getInstance(vector("9_4_t2"));
        assertEquals(Integer.valueOf(C509SignatureAlgorithm.ECDH_POP_SHA384_HMAC_SHA384),
            sha384.getSubjectSignatureAlgorithm().getRegistryValue());
        dhSig = DhSigStatic.getInstance(sha384.getSignature());
        assertEquals(new X500Name("CN=selfsign-secp384r1"), dhSig.getIssuerAndSerial().getName());
        assertEquals(BigInteger.valueOf(0x1234), dhSig.getIssuerAndSerial().getSerialNumber().getValue());
        assertEquals(48, dhSig.getHashValue().length);

        // and the same signature value re-encodes identically from the X.509 form
        byte[] t2 = vector("9_4_t2");
        byte[] recreated = C509CertificationRequest.create(sha384.getTBSCertificationRequestEncoded(),
            sha384.getSignature(), UNCOMPRESSED).getEncoded();
        assertTrue(Arrays.areEqual(t2, recreated));
    }

    public void testDhSigStaticMalformed()
        throws Exception
    {
        byte[] t2 = vector("9_4_t2");
        byte[][] items = splitArray(t2);
        byte[][] sig = splitArray(items[6]);

        // two element array
        checkRejected(join(items, 6, join(new byte[][]{ sig[0], sig[2] }, true)),
            "C509 DhSigStatic array must have 3 elements");

        // serial number with a leading zero octet
        checkRejected(join(items, 6, join(new byte[][]{ sig[0], byteString(Hex.decode("001234")), sig[2] }, true)),
            "C509 certificateSerialNumber with leading zero octet");

        // a hash value that is not a byte string
        checkRejected(join(items, 6, join(new byte[][]{ sig[0], sig[1], integerItem(1) }, true)),
            "CBOR major type 2 expected, found 0");

        // trailing data inside the array item
        checkRejected(join(items, 6, Arrays.concatenate(items[6], integerItem(0))),
            "unexpected trailing data after CBOR item");
    }

    public void testPrivateKeyPossessionStatementVectors()
        throws Exception
    {
        // Section 9.6 names the signature certificate; Section 9.7 carries it
        C509CertificationRequest named = C509CertificationRequest.getInstance(vector("9_6_t3"));
        C509Attribute attribute = named.getAttributes()[0];
        assertEquals(Long.valueOf(C509Attribute.PRIVATE_KEY_POSSESSION_STATEMENT), attribute.getRegistryValue());
        C509PrivateKeyPossessionStatement statement =
            C509PrivateKeyPossessionStatement.getInstance(attribute.getValueEncoding());
        assertEquals(new X500Name("CN=demo issuer"), statement.getIssuer());
        assertEquals(BigInteger.valueOf(2), statement.getSerialNumber());
        assertNull(statement.getCertificate());
        assertTrue(Arrays.areEqual(attribute.getValueEncoding(), statement.getEncoded()));

        C509CertificationRequest withCert = C509CertificationRequest.getInstance(vector("9_7_t3"));
        statement = C509PrivateKeyPossessionStatement.getInstance(withCert.getAttributes()[0].getValueEncoding());
        assertEquals(new X500Name("CN=simple-selfsign-ed25519"), statement.getIssuer());
        assertEquals(BigInteger.valueOf(0x1234), statement.getSerialNumber());
        assertEquals(C509Certificate.TYPE_REENCODED_X509, statement.getCertificate().getCertificateType());

        // the embedded certificate reconstructs to the one in the PKCS#10 attribute
        CertificationRequest pkcs10 = CertificationRequest.getInstance(vector("9_7_pkcs10"));
        Attribute x509Attribute = Attribute.getInstance(
            pkcs10.getCertificationRequestInfo().getAttributes().getObjectAt(0));
        PrivateKeyPossessionStatement x509Statement =
            PrivateKeyPossessionStatement.getInstance(x509Attribute.getAttrValues().getObjectAt(0));
        assertTrue(Arrays.areEqual(x509Statement.getEncoded(ASN1Encoding.DER),
            statement.toPrivateKeyPossessionStatement().getEncoded(ASN1Encoding.DER)));
        assertTrue(Arrays.areEqual(x509Statement.getCert().getEncoded(ASN1Encoding.DER),
            statement.getCertificate().toX509Certificate().getEncoded(ASN1Encoding.DER)));

        // the type 2 request of Section 9.7 embeds the type 2 form of the same certificate
        C509CertificationRequest nativeRequest = C509CertificationRequest.getInstance(vector("9_7_t2"));
        C509PrivateKeyPossessionStatement nativeStatement =
            C509PrivateKeyPossessionStatement.getInstance(nativeRequest.getAttributes()[0].getValueEncoding());
        assertEquals(C509Certificate.TYPE_NATIVE, nativeStatement.getCertificate().getCertificateType());
        assertEquals(statement.getIssuer(), nativeStatement.getCertificate().getIssuer());
        assertEquals(statement.getSerialNumber(), nativeStatement.getCertificate().getSerialNumber());
    }

    public void testNativeRequestWithPossessionStatement()
        throws Exception
    {
        // rebuild the unsigned type 2 requests of Sections 9.6 and 9.7 from their parts
        AlgorithmIdentifier unsigned = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_unsigned);
        String[] tags = { "9_6", "9_7" };
        for (int i = 0; i != tags.length; i++)
        {
            byte[] t2 = vector(tags[i] + "_t2");
            C509CertificationRequest expected = C509CertificationRequest.getInstance(t2);
            C509PrivateKeyPossessionStatement statement = C509PrivateKeyPossessionStatement.getInstance(
                expected.getAttributes()[0].getValueEncoding());
            if (statement.getCertificate() != null)
            {
                // the certificate constructor names it by its own issuer and serial number
                statement = new C509PrivateKeyPossessionStatement(statement.getCertificate());
            }

            byte[] tbs = C509CertificationRequest.createTBSCertificationRequest(C509CertificationRequest.TYPE_NATIVE,
                unsigned, expected.getSubject(), expected.getSubjectPublicKeyInfo(), null, null, statement,
                UNCOMPRESSED);
            C509CertificationRequest rebuilt = C509CertificationRequest.create(tbs, new byte[0], UNCOMPRESSED);
            assertTrue(tags[i] + ": rebuilt request differs", Arrays.areEqual(t2, rebuilt.getEncoded()));
        }
    }

    public void testPrivateKeyPossessionStatementMalformed()
        throws Exception
    {
        byte[] t3 = vector("9_7_t3");
        byte[][] items = splitArray(t3);
        byte[][] attributes = splitArray(items[5]);
        byte[][] statement = splitArray(attributes[1]);

        // two element array
        checkRejected(join(items, 5, join(new byte[][]{ attributes[0],
            join(new byte[][]{ statement[0], statement[1] }, true) }, true)),
            "C509 PrivateKeyPossessionStatement array must have 3 elements");

        // the certificate must be C509CertData or null
        checkRejected(join(items, 5, join(new byte[][]{ attributes[0],
            join(new byte[][]{ statement[0], statement[1], integerItem(0) }, true) }, true)),
            "C509 PrivateKeyPossessionStatement cert must be C509CertData or null");

        // a malformed embedded certificate
        checkRejected(join(items, 5, join(new byte[][]{ attributes[0],
            join(new byte[][]{ statement[0], statement[1], byteString(new byte[]{ (byte)0x8B }) }, true) }, true)),
            "CBOR array count exceeds remaining data");

        // a type 3 request carrying the type 2 certificate of Section 9.7.4 parses, but
        // has no RFC 2986 form
        byte[][] nativeAttributes = splitArray(splitArray(vector("9_7_t2"))[5]);
        C509CertificationRequest mixed = C509CertificationRequest.getInstance(
            join(items, 5, join(new byte[][]{ attributes[0], nativeAttributes[1] }, true)));
        try
        {
            mixed.toCertificationRequest();
            fail("reconstructed a request carrying a natively signed certificate");
        }
        catch (IOException e)
        {
            assertEquals(
                "C509 PrivateKeyPossessionStatement carries a natively signed certificate, which has no X.509 form",
                e.getMessage());
        }
    }

    public void testTemplateVectors()
        throws Exception
    {
        for (int i = 1; i <= 4; i++)
        {
            byte[] encoding = vector("12_" + i + "_template");
            assertTrue("12." + i + ": re-encoding differs",
                Arrays.areEqual(encoding, C509CertificationRequestTemplate.getInstance(encoding).getEncoded()));
        }
    }

    private static void checkRejected(byte[] encoding, String message)
        throws IOException
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

    // the array with the item at the given index replaced
    private static byte[] join(byte[][] items, int index, byte[] replacement)
        throws IOException
    {
        byte[][] copy = new byte[items.length][];
        System.arraycopy(items, 0, copy, 0, items.length);
        copy[index] = replacement;
        return join(copy, true);
    }

    private static byte[] byteString(byte[] value)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeByteString(value);
        return bOut.toByteArray();
    }

    private static byte[] integerItem(long value)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeInteger(value);
        return bOut.toByteArray();
    }
}
