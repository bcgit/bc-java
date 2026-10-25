package org.bouncycastle.cbor.c509.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.PrivateKeyPossessionStatement;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.c509.C509Attribute;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cbor.c509.C509CertificationRequest;
import org.bouncycastle.cbor.c509.C509CertificationRequestTemplate;
import org.bouncycastle.cbor.c509.C509ConversionOptions;
import org.bouncycastle.cbor.c509.C509PrivateKeyPossessionStatement;
import org.bouncycastle.cbor.c509.C509SignatureAlgorithm;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * Tests driven by the vectors of draft-ietf-cose-c509-test-vectors-02, held in
 * bc-test-data under c509/test-vectors (see its README). Every certificate,
 * certification request and template the draft publishes is converted, reconstructed
 * and round-tripped; signature verification is covered on the pkix side.
 * <p>
 * The draft aligns with draft-ietf-cose-cbor-encoded-cert-20 where this code tracks
 * -21: the only difference that reaches a vector is Section 3.10's
 * subjectDirectoryAttributes extension, which -20 coded as extension value 24 and -21
 * removed from the registry, so its C509 forms are expected to be refused.
 */
public class C509TestVectorsTest
    extends TestCase
{
    private static final C509ConversionOptions UNCOMPRESSED =
        C509ConversionOptions.DEFAULT.withPointCompression(false);

    // certificate vectors publishing all of the X.509, type 3 and type 2 forms
    private static final String[] CERT_TAGS = {
        "2", "3_1", "3_2", "3_3", "3_5", "3_6", "3_7", "3_8", "3_9", "3_11", "3_12", "3_13", "3_14", "3_15",
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

        // Section 7 publishes no type 2 form
        checkCertificate("7", vector("7_x509"), vector("7_t3"), null, UNCOMPRESSED);
    }

    public void testSubjectDirectoryAttributesVector()
        throws Exception
    {
        // Section 3.10 uses the -20 int-coded subjectDirectoryAttributes (extension
        // value 24), which -21 removed from the registry
        String[] forms = { "3_10_t3", "3_10_t2" };
        for (int i = 0; i != forms.length; i++)
        {
            try
            {
                C509Certificate.getInstance(vector(forms[i]));
                fail(forms[i] + ": accepted the withdrawn extension value 24");
            }
            catch (IOException e)
            {
                assertEquals("unknown C509 extension value: 24", e.getMessage());
            }
        }

        // under -21 the extension goes in the generic form, which still round-trips
        byte[] der = vector("3_10_x509");
        C509Certificate c509 = C509Certificate.fromX509Certificate(Certificate.getInstance(der), UNCOMPRESSED);
        assertTrue(Arrays.areEqual(der, c509.toX509Certificate().getEncoded(ASN1Encoding.DER)));
        boolean found = false;
        for (int i = 0; i != c509.getExtensions().size(); i++)
        {
            org.bouncycastle.cbor.c509.C509Extension ext = c509.getExtensions().getExtension(i);
            if (org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.equals(ext.getExtnId()))
            {
                assertNull(ext.getRegistryValue());
                found = true;
            }
        }
        assertTrue(found);
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
            String tag = "8_" + i;
            // Section 8.2 publishes no type 2 form
            checkCertificationRequest(tag, vector(tag + "_pkcs10"), vector(tag + "_t3"),
                i == 2 ? null : vector(tag + "_t2"));
        }
    }

    public void testDhSigStaticVectors()
        throws Exception
    {
        // Sections 8.3 and 8.5: the bare hashValue stands for a DhSigStatic without issuerAndSerial
        C509CertificationRequest sha256 = C509CertificationRequest.getInstance(vector("8_3_t2"));
        assertEquals(Integer.valueOf(C509SignatureAlgorithm.ECDH_POP_SHA256_HMAC_SHA256),
            sha256.getSubjectSignatureAlgorithm().getRegistryValue());
        DhSigStatic dhSig = DhSigStatic.getInstance(sha256.getSignature());
        assertNull(dhSig.getIssuerAndSerial());
        assertEquals(32, dhSig.getHashValue().length);

        // Section 8.4: the array form carries the issuer and serial number
        C509CertificationRequest sha384 = C509CertificationRequest.getInstance(vector("8_4_t2"));
        assertEquals(Integer.valueOf(C509SignatureAlgorithm.ECDH_POP_SHA384_HMAC_SHA384),
            sha384.getSubjectSignatureAlgorithm().getRegistryValue());
        dhSig = DhSigStatic.getInstance(sha384.getSignature());
        assertEquals(new X500Name("CN=selfsign-secp384r1"), dhSig.getIssuerAndSerial().getName());
        assertEquals(BigInteger.valueOf(0x1234), dhSig.getIssuerAndSerial().getSerialNumber().getValue());
        assertEquals(48, dhSig.getHashValue().length);

        // and the same signature value re-encodes identically from the X.509 form
        byte[] t2 = vector("8_4_t2");
        byte[] recreated = C509CertificationRequest.create(sha384.getTBSCertificationRequestEncoded(),
            sha384.getSignature(), UNCOMPRESSED).getEncoded();
        assertTrue(Arrays.areEqual(t2, recreated));
    }

    public void testDhSigStaticMalformed()
        throws Exception
    {
        byte[] t2 = vector("8_4_t2");
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
        // Section 8.6 names the signature certificate; Section 8.7 carries it
        C509CertificationRequest named = C509CertificationRequest.getInstance(vector("8_6_t3"));
        C509Attribute attribute = named.getAttributes()[0];
        assertEquals(Long.valueOf(C509Attribute.PRIVATE_KEY_POSSESSION_STATEMENT), attribute.getRegistryValue());
        C509PrivateKeyPossessionStatement statement =
            C509PrivateKeyPossessionStatement.getInstance(attribute.getValueEncoding());
        assertEquals(new X500Name("CN=demo issuer"), statement.getIssuer());
        assertEquals(BigInteger.valueOf(2), statement.getSerialNumber());
        assertNull(statement.getCertificate());
        assertTrue(Arrays.areEqual(attribute.getValueEncoding(), statement.getEncoded()));

        C509CertificationRequest withCert = C509CertificationRequest.getInstance(vector("8_7_t3"));
        statement = C509PrivateKeyPossessionStatement.getInstance(withCert.getAttributes()[0].getValueEncoding());
        assertEquals(new X500Name("CN=simple-selfsign-ed25519"), statement.getIssuer());
        assertEquals(BigInteger.valueOf(0x1234), statement.getSerialNumber());
        assertEquals(C509Certificate.TYPE_REENCODED_X509, statement.getCertificate().getCertificateType());

        // the embedded certificate reconstructs to the one in the PKCS#10 attribute
        CertificationRequest pkcs10 = CertificationRequest.getInstance(vector("8_7_pkcs10"));
        Attribute x509Attribute = Attribute.getInstance(
            pkcs10.getCertificationRequestInfo().getAttributes().getObjectAt(0));
        PrivateKeyPossessionStatement x509Statement =
            PrivateKeyPossessionStatement.getInstance(x509Attribute.getAttrValues().getObjectAt(0));
        assertTrue(Arrays.areEqual(x509Statement.getEncoded(ASN1Encoding.DER),
            statement.toPrivateKeyPossessionStatement().getEncoded(ASN1Encoding.DER)));
        assertTrue(Arrays.areEqual(x509Statement.getCert().getEncoded(ASN1Encoding.DER),
            statement.getCertificate().toX509Certificate().getEncoded(ASN1Encoding.DER)));

        // the type 2 request of Section 8.7 embeds the type 2 form of the same certificate
        C509CertificationRequest nativeRequest = C509CertificationRequest.getInstance(vector("8_7_t2"));
        C509PrivateKeyPossessionStatement nativeStatement =
            C509PrivateKeyPossessionStatement.getInstance(nativeRequest.getAttributes()[0].getValueEncoding());
        assertEquals(C509Certificate.TYPE_NATIVE, nativeStatement.getCertificate().getCertificateType());
        assertEquals(statement.getIssuer(), nativeStatement.getCertificate().getIssuer());
        assertEquals(statement.getSerialNumber(), nativeStatement.getCertificate().getSerialNumber());
    }

    public void testNativeRequestWithPossessionStatement()
        throws Exception
    {
        // rebuild the unsigned type 2 requests of Sections 8.6 and 8.7 from their parts
        AlgorithmIdentifier unsigned = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_unsigned);
        String[] tags = { "8_6", "8_7" };
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
        byte[] t3 = vector("8_7_t3");
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

        // a type 3 request carrying the type 2 certificate of Section 8.7.4 parses, but
        // has no RFC 2986 form
        byte[][] nativeAttributes = splitArray(splitArray(vector("8_7_t2"))[5]);
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
        for (int i = 1; i <= 3; i++)
        {
            byte[] encoding = vector("10_" + i + "_template");
            assertTrue("10." + i + ": re-encoding differs",
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
