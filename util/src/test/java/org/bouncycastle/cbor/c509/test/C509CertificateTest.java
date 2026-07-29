package org.bouncycastle.cbor.c509.test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.cbor.c509.C509AttributeType;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cbor.c509.C509ConversionOptions;
import org.bouncycastle.cbor.c509.C509ExtensionType;
import org.bouncycastle.cbor.c509.C509PublicKeyAlgorithm;
import org.bouncycastle.cbor.c509.C509SignatureAlgorithm;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * Tests driven by the worked examples in Appendix A of
 * draft-ietf-cose-cbor-encoded-cert-20. The A.1 and A.2 C509 encodings are given in
 * the draft itself; the A.3, A.4 and A.5 expected encodings were generated from the
 * appendix's CBOR diagnostic notation and match the certificate sizes the draft
 * documents (836 and 1296 bytes for A.3 and A.4).
 */
public class C509CertificateTest
    extends TestCase
{
    private static byte[] vector(String name)
        throws IOException
    {
        InputStream in = TestResourceFinder.findTestResource("c509", name + ".hex");
        return Hex.decode(Strings.fromByteArray(Streams.readAll(in)).trim());
    }

    private void checkReencoding(String name, C509ConversionOptions options)
        throws IOException
    {
        byte[] der = vector(name + "_x509");
        byte[] expected = vector(name + "_c509_reencoded");

        // DER -> C509 must match the draft's expected encoding exactly
        C509Certificate c509 = C509Certificate.fromX509Certificate(
            Certificate.getInstance(der), options);
        assertTrue(name + ": C509 encoding differs", Arrays.areEqual(expected, c509.getEncoded()));

        // C509 -> DER must reproduce the original certificate byte for byte
        C509Certificate parsed = C509Certificate.getInstance(expected);
        assertTrue(name + ": reconstructed DER differs",
            Arrays.areEqual(der, parsed.toX509Certificate().getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER)));

        // parse and re-encode is the identity
        assertTrue(name + ": re-encoding differs", Arrays.areEqual(expected, parsed.getEncoded()));
    }

    public void testA1RFC7925Profile()
        throws Exception
    {
        checkReencoding("a1", C509ConversionOptions.DEFAULT);

        C509Certificate cert = C509Certificate.getInstance(vector("a1_c509_reencoded"));
        assertEquals(C509Certificate.TYPE_REENCODED_X509, cert.getCertificateType());
        assertEquals(BigInteger.valueOf(128269), cert.getSerialNumber());
        assertEquals(Integer.valueOf(C509SignatureAlgorithm.ECDSA_WITH_SHA256),
            cert.getIssuerSignatureAlgorithm().getRegistryValue());
        assertEquals("CN=RFC test CA", cert.getIssuer().toString());
        assertEquals(1672531200L, cert.getNotBefore());
        assertEquals(1767225600L, cert.getNotAfter());
        assertEquals("CN=01-23-45-FF-FE-67-89-AB", cert.getSubject().toString());
        assertEquals(Integer.valueOf(C509PublicKeyAlgorithm.EC_SECP256R1),
            cert.getSubjectPublicKeyAlgorithm().getRegistryValue());
        assertEquals(1, cert.getExtensions().size());
        assertEquals(Integer.valueOf(C509ExtensionType.KEY_USAGE),
            cert.getExtensions().getExtension(0).getRegistryValue());
        assertFalse(cert.getExtensions().getExtension(0).isCritical());

        // the decompressed public key must equal the DER original's
        Certificate x509 = Certificate.getInstance(vector("a1_x509"));
        assertTrue(Arrays.areEqual(x509.getTBSCertificate().getSubjectPublicKeyInfo().getEncoded(),
            cert.getSubjectPublicKeyInfo().getEncoded()));
    }

    public void testA1NativeCertificate()
        throws Exception
    {
        byte[] encoding = vector("a1_c509_native");
        C509Certificate cert = C509Certificate.getInstance(encoding);

        assertEquals(C509Certificate.TYPE_NATIVE, cert.getCertificateType());
        assertEquals(BigInteger.valueOf(128269), cert.getSerialNumber());
        assertTrue(Arrays.areEqual(encoding, cert.getEncoded()));

        // a native certificate's signature is over the TBSCertificate CBOR sequence:
        // the whole encoding minus the leading array header (1 byte) and the trailing
        // signature value item
        byte[] tbs = cert.getTBSCertificateEncoded();
        assertTrue(Arrays.areEqual(Arrays.copyOfRange(encoding, 1, encoding.length - 66), tbs));

        // verify the signature with the issuer public key of Appendix A.1.4
        X9ECParameters p256 = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters domain = new ECDomainParameters(p256.getCurve(), p256.getG(), p256.getN(), p256.getH());
        ECPublicKeyParameters issuerKey = new ECPublicKeyParameters(
            p256.getCurve().decodePoint(Hex.decode(
                "02AE4CDB01F614DEFC7121285FDC7F5C6D1D42C95647F061BA0080DF678867845E")),
            domain);
        DSADigestSigner verifier = new DSADigestSigner(new ECDSASigner(), new SHA256Digest());
        verifier.init(false, issuerKey);
        verifier.update(tbs, 0, tbs.length);
        assertTrue("native signature must verify over the TBS CBOR sequence",
            verifier.verifySignature(cert.getSignature()));

        // and the re-encoded (type 3) A.1 certificate's signature must verify over
        // the reconstructed DER TBSCertificate
        C509Certificate reencoded = C509Certificate.getInstance(vector("a1_c509_reencoded"));
        byte[] derTbs = reencoded.toX509Certificate().getTBSCertificate()
            .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        verifier.init(false, issuerKey);
        verifier.update(derTbs, 0, derTbs.length);
        assertTrue("re-encoded signature must verify over the reconstructed DER",
            verifier.verifySignature(reencoded.getSignature()));
    }

    public void testA2IEEE8021ARProfile()
        throws Exception
    {
        checkReencoding("a2", C509ConversionOptions.DEFAULT);

        C509Certificate cert = C509Certificate.getInstance(vector("a2_c509_reencoded"));
        // no expiration date (GeneralizedTime 99991231235959Z encoded as null)
        assertEquals(C509Certificate.NO_EXPIRATION_DATE, cert.getNotAfter());
        assertEquals(5, cert.getExtensions().size());
        // hardwareModuleName otherName in the subject alternative name survives
        assertEquals(Integer.valueOf(C509ExtensionType.SUBJECT_ALT_NAME),
            cert.getExtensions().getExtension(4).getRegistryValue());
    }

    public void testA3CABBaselineECDSA()
        throws Exception
    {
        byte[] expected = vector("a3_c509_reencoded");
        assertEquals("draft documents 836 bytes for the A.3 encoding", 836, expected.length);
        checkReencoding("a3", C509ConversionOptions.DEFAULT);
    }

    public void testA4CABBaselineRSA()
        throws Exception
    {
        byte[] expected = vector("a4_c509_reencoded");
        assertEquals("draft documents 1296 bytes for the A.4 encoding", 1296, expected.length);
        checkReencoding("a4", C509ConversionOptions.DEFAULT);

        C509Certificate cert = C509Certificate.getInstance(expected);
        assertEquals(Integer.valueOf(C509SignatureAlgorithm.RSASSA_PKCS1_V15_WITH_SHA256),
            cert.getIssuerSignatureAlgorithm().getRegistryValue());
        assertEquals(Integer.valueOf(C509PublicKeyAlgorithm.RSA),
            cert.getSubjectPublicKeyAlgorithm().getRegistryValue());
    }

    public void testA5IPAddrBlocks()
        throws Exception
    {
        // the A.5 example is encoded without point compression
        checkReencoding("a5", C509ConversionOptions.DEFAULT.withPointCompression(false));

        C509Certificate cert = C509Certificate.getInstance(vector("a5_c509_reencoded"));
        assertTrue(cert.isSelfIssued());
        assertEquals(cert.getSubject(), cert.getIssuer());
        assertEquals(3, cert.getExtensions().size());
        assertEquals(Integer.valueOf(C509ExtensionType.IP_ADDR_BLOCKS),
            cert.getExtensions().getExtension(1).getRegistryValue());
        assertEquals(Integer.valueOf(C509ExtensionType.IP_ADDR_BLOCKS_V2),
            cert.getExtensions().getExtension(2).getRegistryValue());
    }

    public void testRegistryLookups()
        throws Exception
    {
        assertEquals(Integer.valueOf(C509AttributeType.COMMON_NAME),
            C509AttributeType.getValue(C509AttributeType.getOID(C509AttributeType.COMMON_NAME)));
        assertEquals("2.5.4.3", C509AttributeType.getOID(C509AttributeType.COMMON_NAME).getId());
        assertEquals("2.5.29.15", C509ExtensionType.getOID(C509ExtensionType.KEY_USAGE).getId());
        assertNull(C509ExtensionType.getOID(23));
        assertEquals("1.2.840.10045.4.3.2",
            C509SignatureAlgorithm.getAlgorithmIdentifier(C509SignatureAlgorithm.ECDSA_WITH_SHA256)
                .getAlgorithm().getId());
        assertNull(C509SignatureAlgorithm.getAlgorithmIdentifier(100));
        assertEquals("1.2.840.10045.2.1",
            C509PublicKeyAlgorithm.getAlgorithmIdentifier(C509PublicKeyAlgorithm.EC_SECP256R1)
                .getAlgorithm().getId());
        assertTrue(C509PublicKeyAlgorithm.isWeierstrassPoint(C509PublicKeyAlgorithm.EC_BRAINPOOLP384R1));
        assertFalse(C509PublicKeyAlgorithm.isWeierstrassPoint(C509PublicKeyAlgorithm.ED25519));
    }

    public void testMalformedCertificatesRejected()
        throws Exception
    {
        byte[] good = vector("a1_c509_reencoded");

        // truncated at every prefix length must fail cleanly with an IOException
        for (int len = 0; len != good.length; len++)
        {
            byte[] truncated = Arrays.copyOfRange(good, 0, len);
            try
            {
                C509Certificate.getInstance(truncated);
                fail("truncated certificate accepted at length " + len);
            }
            catch (IOException e)
            {
                // expected
            }
        }

        // trailing garbage
        expectRejected(Arrays.append(good, (byte)0), "trailing data");

        // unknown certificate type (array with first element 4)
        byte[] wrongType = Arrays.clone(good);
        wrongType[1] = 0x04;
        expectRejected(wrongType, "unknown certificate type");

        // serial number with a leading zero octet is not a valid ~biguint
        byte[] paddedSerial = Hex.decode(
            "8B" + "03" + "440001F50D" + Hex.toHexString(Arrays.copyOfRange(good, 6, good.length)));
        expectRejected(paddedSerial, "serial number with leading zero");
    }

    public void testNotAfterMustUseNullFor9999()
        throws Exception
    {
        // take the A.2 vector (which has notAfter = null) and replace the null with
        // the equivalent uint 253402300799 (0x3AFFF44080FF... actually 1B 0000003AFFF4417F)
        byte[] good = vector("a2_c509_reencoded");
        int nullIndex = -1;
        // the notAfter null is the byte 0xF6 following the 5-byte notBefore item
        // (1A 5C 52 DC 0C); find that pattern
        byte[] pattern = Hex.decode("1A5C52DC0CF6");
        for (int i = 0; i < good.length - pattern.length; i++)
        {
            boolean match = true;
            for (int j = 0; j != pattern.length; j++)
            {
                if (good[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                nullIndex = i + 5;
                break;
            }
        }
        assertTrue(nullIndex > 0);
        byte[] modified = new byte[good.length + 8];
        System.arraycopy(good, 0, modified, 0, nullIndex);
        byte[] uint9999 = Hex.decode("1B0000003AFFF4417F");
        System.arraycopy(uint9999, 0, modified, nullIndex, uint9999.length);
        System.arraycopy(good, nullIndex + 1, modified, nullIndex + uint9999.length,
            good.length - nullIndex - 1);
        expectRejected(modified, "notAfter 99991231235959Z as uint");
    }

    public void testCertificationRequestTemplateRoundTrip()
        throws Exception
    {
        // no worked example exists in the draft appendices yet, so this pins the
        // encode/parse round trip of a template exercising every field form
        org.bouncycastle.cbor.c509.C509CertificationRequestTemplate template =
            new org.bouncycastle.cbor.c509.C509CertificationRequestTemplate(
                org.bouncycastle.cbor.c509.C509CertificationRequestTemplate.TYPE_SIMPLE,
                new int[]{ 2, 3 },
                new org.bouncycastle.cbor.c509.C509AlgorithmIdentifier[]
                    { org.bouncycastle.cbor.c509.C509AlgorithmIdentifier.forSignatureAlgorithm(
                        C509SignatureAlgorithm.getAlgorithmIdentifier(C509SignatureAlgorithm.ECDSA_WITH_SHA256)) },
                new org.bouncycastle.cbor.c509.C509CertificationRequestTemplate.RDNAttributeTemplate[]
                    {
                        new org.bouncycastle.cbor.c509.C509CertificationRequestTemplate.RDNAttributeTemplate(
                            C509AttributeType.COMMON_NAME, 1, 1, null),
                        new org.bouncycastle.cbor.c509.C509CertificationRequestTemplate.RDNAttributeTemplate(
                            C509AttributeType.ORGANIZATION, 0, 1, Hex.decode("6161")) // the CBOR text string "a"
                    },
                new org.bouncycastle.cbor.c509.C509AlgorithmIdentifier[]
                    { org.bouncycastle.cbor.c509.C509AlgorithmIdentifier.forPublicKeyAlgorithm(
                        C509PublicKeyAlgorithm.getAlgorithmIdentifier(C509PublicKeyAlgorithm.EC_SECP256R1)) },
                new org.bouncycastle.cbor.c509.C509CertificationRequestTemplate.ExtensionTemplate[]
                    {
                        new org.bouncycastle.cbor.c509.C509CertificationRequestTemplate.ExtensionTemplate(
                            C509ExtensionType.KEY_USAGE, false, Hex.decode("01"))
                    });

        byte[] encoding = template.getEncoded();
        org.bouncycastle.cbor.c509.C509CertificationRequestTemplate parsed =
            org.bouncycastle.cbor.c509.C509CertificationRequestTemplate.getInstance(encoding);
        assertTrue(Arrays.areEqual(encoding, parsed.getEncoded()));
        assertEquals(2, parsed.getCertificationRequestTypes().length);
        assertEquals(2, parsed.getSubjectTemplate().length);
        assertNull(parsed.getSubjectTemplate()[0].getValueEncoding());
        assertEquals(1, parsed.getExtensionsTemplate().length);
        assertFalse(parsed.getExtensionsTemplate()[0].isOptional());
    }

    public void testMalformedECDSASignatureComponents()
        throws Exception
    {
        // an ECDSA-declared certificate whose signature SEQUENCE holds a non-INTEGER
        // element must be reported by the signature value codec itself, not leak an
        // unchecked exception to the outer conversion boundary
        Certificate good = Certificate.getInstance(vector("a1_x509"));
        org.bouncycastle.asn1.ASN1EncodableVector v;
        v = new org.bouncycastle.asn1.ASN1EncodableVector();
        v.add(good.getTBSCertificate());
        v.add(good.getSignatureAlgorithm());
        v.add(new org.bouncycastle.asn1.DERBitString(new org.bouncycastle.asn1.DERSequence(
            new org.bouncycastle.asn1.ASN1Encodable[]{
                new org.bouncycastle.asn1.DEROctetString(new byte[4]),
                new org.bouncycastle.asn1.ASN1Integer(1) }).getEncoded()));
        byte[] malformed = new org.bouncycastle.asn1.DERSequence(v).getEncoded();

        try
        {
            C509Certificate.fromX509Certificate(malformed);
            fail("malformed ECDSA signature accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed ECDSA signature value", e.getMessage());
        }

        // and a negative r: per RFC 3279 sec. 2.2.3 the components are INTEGERs, so a
        // negative one must be rejected as malformed rather than reinterpreted unsigned
        v = new org.bouncycastle.asn1.ASN1EncodableVector();
        v.add(good.getTBSCertificate());
        v.add(good.getSignatureAlgorithm());
        v.add(new org.bouncycastle.asn1.DERBitString(new org.bouncycastle.asn1.DERSequence(
            new org.bouncycastle.asn1.ASN1Encodable[]{
                new org.bouncycastle.asn1.ASN1Integer(-1),
                new org.bouncycastle.asn1.ASN1Integer(1) }).getEncoded()));
        byte[] negativeR = new org.bouncycastle.asn1.DERSequence(v).getEncoded();

        try
        {
            C509Certificate.fromX509Certificate(negativeR);
            fail("negative ECDSA signature component accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed ECDSA signature value", e.getMessage());
        }

        // r = 0 is structurally well-formed DER but can never be a valid ECDSA
        // component (r, s >= 1): rejected at the transcoding boundary rather than
        // left for a verifier to discover
        v = new org.bouncycastle.asn1.ASN1EncodableVector();
        v.add(good.getTBSCertificate());
        v.add(good.getSignatureAlgorithm());
        v.add(new org.bouncycastle.asn1.DERBitString(new org.bouncycastle.asn1.DERSequence(
            new org.bouncycastle.asn1.ASN1Encodable[]{
                new org.bouncycastle.asn1.ASN1Integer(0),
                new org.bouncycastle.asn1.ASN1Integer(1) }).getEncoded()));
        byte[] zeroR = new org.bouncycastle.asn1.DERSequence(v).getEncoded();

        try
        {
            C509Certificate.fromX509Certificate(zeroR);
            fail("zero ECDSA signature component accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed ECDSA signature value", e.getMessage());
        }

        // and the decode direction: a C509 certificate whose r || s halves are zero
        // must be rejected on parse
        byte[] zeroSig = vector("a1_c509_reencoded");
        java.util.Arrays.fill(zeroSig, zeroSig.length - 64, zeroSig.length, (byte)0);
        try
        {
            C509Certificate.getInstance(zeroSig);
            fail("zero r || s halves accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed ECDSA signature value", e.getMessage());
        }
    }

    public void testMutationalRobustness()
        throws Exception
    {
        // every random single-byte mutation of a valid certificate must either parse
        // or be rejected with an IOException - never any other exception type
        String[] names = new String[]{ "a1_c509_reencoded", "a1_c509_native", "a2_c509_reencoded",
            "a3_c509_reencoded", "a4_c509_reencoded", "a5_c509_reencoded" };
        java.util.Random random = new java.util.Random(1234567L);
        for (int n = 0; n != names.length; n++)
        {
            byte[] good = vector(names[n]);
            for (int iter = 0; iter != 2000; iter++)
            {
                byte[] mutated = Arrays.clone(good);
                int mutations = 1 + random.nextInt(4);
                for (int m = 0; m != mutations; m++)
                {
                    mutated[random.nextInt(mutated.length)] = (byte)random.nextInt(256);
                }
                try
                {
                    C509Certificate cert = C509Certificate.getInstance(mutated);
                    // accepted mutations must still re-encode to themselves
                    assertTrue(Arrays.areEqual(mutated, cert.getEncoded()));
                }
                catch (IOException e)
                {
                    // the only acceptable failure at a decode boundary
                }
            }
        }
    }

    private void expectRejected(byte[] encoding, String description)
    {
        try
        {
            C509Certificate.getInstance(encoding);
            fail("accepted " + description);
        }
        catch (IOException e)
        {
            // expected
        }
    }
}
