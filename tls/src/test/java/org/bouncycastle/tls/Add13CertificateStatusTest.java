package org.bouncycastle.tls;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Integers;

/**
 * How {@link TlsUtils#add13CertificateStatus(Certificate, CertificateStatus)} distributes a server's
 * OCSP staples over the CertificateEntry extensions of RFC 8446 sec. 4.4.2.1, and what it does with a
 * response the entry cannot carry.
 * <p/>
 * {@link Certificate#encode} writes an entry's whole extensions block with a 16-bit length, so a
 * large enough response overflows it. Nothing bounds an OCSP response to a size that rules this out -
 * a responder chooses what it sends, and may include a certificate chain of its own - so the response
 * that does not fit has to be dropped. Letting it through fails the handshake at encode time, which
 * would make an oversized staple worse than no staple at all.
 */
public class Add13CertificateStatusTest
    extends TestCase
{
    /**
     * The largest response an otherwise extension-free entry can carry: the entry's extensions block
     * is written with writeOpaque16, and this extension costs four bytes of type and length plus a
     * CertificateStatus body of a status type and an opaque24 length ahead of the response itself.
     */
    private static final int MAX_DER_LENGTH = 65535 - 4 - 1 - 3;

    public void testStapleIsAttachedToEveryEntryAnsweredFor()
        throws Exception
    {
        Certificate certificate = certificate(2, null);

        Certificate result = TlsUtils.add13CertificateStatus(certificate, ocspMulti(new OCSPResponse[]
        {
            ocspResponse(64),
            ocspResponse(64)
        }));

        assertNotSame("a new Certificate should have been built", certificate, result);
        assertNotNull(stapleOf(result, 0));
        assertNotNull(stapleOf(result, 1));
    }

    /**
     * The boundary itself is carried, so the guard is a limit rather than a margin.
     */
    public void testLargestCarryableResponseIsStapled()
        throws Exception
    {
        Certificate certificate = certificate(1, null);

        Certificate result = TlsUtils.add13CertificateStatus(certificate,
            ocspSingle(ocspResponseOfEncodedLength(MAX_DER_LENGTH)));

        assertNotNull("the largest response that fits should be stapled", stapleOf(result, 0));
    }

    /**
     * One byte over, and the staple is dropped - not turned into a fatal alert from Certificate.encode.
     */
    public void testOversizedResponseIsDroppedRatherThanFatal()
        throws Exception
    {
        Certificate certificate = certificate(1, null);

        Certificate result = TlsUtils.add13CertificateStatus(certificate,
            ocspSingle(ocspResponseOfEncodedLength(MAX_DER_LENGTH + 1)));

        assertSame("with nothing stapled the original Certificate should come back", certificate, result);
        assertNull(stapleOf(result, 0));

        // the real point: what comes back is encodable, where the unguarded form overflowed here
        assertEntryIsEncodable(result, 0);
    }

    /**
     * An oversized response for one certificate does not cost the rest of the chain its staples.
     */
    public void testOversizedResponseDoesNotSuppressTheOthers()
        throws Exception
    {
        Certificate certificate = certificate(2, null);

        Certificate result = TlsUtils.add13CertificateStatus(certificate, ocspMulti(new OCSPResponse[]
        {
            ocspResponseOfEncodedLength(MAX_DER_LENGTH + 1),
            ocspResponse(64)
        }));

        assertNull("the oversized response should have been dropped", stapleOf(result, 0));
        assertNotNull("the response that fits should still be stapled", stapleOf(result, 1));
        assertEntryIsEncodable(result, 0);
        assertEntryIsEncodable(result, 1);
    }

    /**
     * An extension the server attached itself takes up room in the same block, so the limit is on what
     * is left rather than on the response alone.
     */
    public void testExistingExtensionsCountTowardTheLimit()
        throws Exception
    {
        Hashtable existing = new Hashtable();
        existing.put(Integers.valueOf(ExtensionType.signed_certificate_timestamp), new byte[1024]);

        Certificate certificate = certificate(1, existing);

        Certificate result = TlsUtils.add13CertificateStatus(certificate,
            ocspSingle(ocspResponseOfEncodedLength(MAX_DER_LENGTH - 1024 - 4)));

        assertNotNull("a response that fits alongside the existing extension should be stapled",
            stapleOf(result, 0));
        assertEntryIsEncodable(result, 0);

        Certificate tooBig = TlsUtils.add13CertificateStatus(certificate(1, existing),
            ocspSingle(ocspResponseOfEncodedLength(MAX_DER_LENGTH - 1024 - 4 + 1)));

        assertNull("the existing extension should have left no room for one byte more",
            stapleOf(tooBig, 0));
        assertEntryIsEncodable(tooBig, 0);
    }

    private static byte[] stapleOf(Certificate certificate, int index)
    {
        Hashtable extensions = certificate.getCertificateEntryAt(index).getExtensions();

        return null == extensions
            ?   null
            :   (byte[])extensions.get(TlsExtensionsUtils.EXT_status_request);
    }

    /**
     * The constraint {@link Certificate#encode} applies: it builds each entry's extensions block with
     * {@link TlsProtocol#writeExtensionsData(Hashtable)} and writes it with
     * {@link TlsUtils#writeOpaque16}, so a block that is not a valid uint16 is a fatal alert there.
     * Asserted directly rather than by encoding, which would need a negotiated TLS 1.3 context.
     */
    private static void assertEntryIsEncodable(Certificate certificate, int index)
        throws IOException
    {
        Hashtable extensions = certificate.getCertificateEntryAt(index).getExtensions();

        int length = null == extensions ? 0 : TlsProtocol.writeExtensionsData(extensions).length;

        assertTrue("the entry's extensions block does not fit the 16-bit length Certificate.encode"
            + " writes: " + length, TlsUtils.isValidUint16(length));
    }

    private static Certificate certificate(int count, Hashtable extensions)
    {
        CertificateEntry[] certificateEntryList = new CertificateEntry[count];
        for (int i = 0; i < count; ++i)
        {
            certificateEntryList[i] = new CertificateEntry(new StubTlsCertificate(),
                null == extensions ? null : new Hashtable(extensions));
        }

        return new Certificate(CertificateType.X509, TlsUtils.EMPTY_BYTES, certificateEntryList);
    }

    private static CertificateStatus ocspSingle(OCSPResponse ocspResponse)
    {
        return new CertificateStatus(CertificateStatusType.ocsp, ocspResponse);
    }

    private static CertificateStatus ocspMulti(OCSPResponse[] ocspResponses)
    {
        Vector ocspResponseList = new Vector(ocspResponses.length);
        for (int i = 0; i < ocspResponses.length; ++i)
        {
            ocspResponseList.addElement(ocspResponses[i]);
        }

        return new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList);
    }

    private static OCSPResponse ocspResponse(int payloadLength)
    {
        return new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL),
            new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic,
                new DEROctetString(new byte[payloadLength])));
    }

    /**
     * A response encoding to exactly <code>derLength</code> bytes, so a test can sit on the limit
     * rather than guess at it. The ASN.1 framing is a fixed overhead once the payload is long enough
     * for its length to take three bytes, so correcting the payload by the shortfall converges at
     * once; the loop is there only to make that an assertion rather than an assumption.
     */
    private static OCSPResponse ocspResponseOfEncodedLength(int derLength)
        throws IOException
    {
        int payloadLength = derLength;

        for (int i = 0; i < 4; ++i)
        {
            OCSPResponse ocspResponse = ocspResponse(payloadLength);

            int actual = ocspResponse.getEncoded(ASN1Encoding.DER).length;
            if (actual == derLength)
            {
                return ocspResponse;
            }

            payloadLength += derLength - actual;
        }

        throw new IllegalStateException("unable to build an OCSPResponse of length " + derLength);
    }

    /**
     * add13CertificateStatus only ever carries the certificate from one entry to the next, so a
     * stand-in keeps the test off the crypto layer and its key material.
     */
    private static class StubTlsCertificate
        implements TlsCertificate
    {
        public TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public Tls13Verifier createVerifier(int signatureScheme) throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public byte[] getEncoded() throws IOException
        {
            return new byte[]{ 0x30, 0x00 };
        }

        public byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException
        {
            return null;
        }

        public BigInteger getSerialNumber()
        {
            return BigInteger.ZERO;
        }

        public String getSigAlgOID()
        {
            throw new UnsupportedOperationException();
        }

        public ASN1Encodable getSigAlgParams() throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public short getLegacySignatureAlgorithm() throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public boolean supportsSignatureAlgorithm(short signatureAlgorithm) throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public TlsCertificate checkUsageInRole(int tlsCertificateRole) throws IOException
        {
            throw new UnsupportedOperationException();
        }
    }
}
