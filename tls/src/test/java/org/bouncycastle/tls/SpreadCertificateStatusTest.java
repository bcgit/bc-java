package org.bouncycastle.tls;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1Encodable;
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
import org.bouncycastle.util.Strings;

/**
 * How {@link TlsUtils#spreadCertificateStatus(Certificate, CertificateStatus)} reads a
 * "certificate_status" message out per certificate, which is what lets
 * {@link TlsServerCertificate#getCertificateStatusAt(int)} answer the same way up to TLS 1.2 as it
 * does for the per-CertificateEntry extensions of TLS 1.3.
 * <p/>
 * The ocsp shape answers for the end-entity certificate alone (RFC 6066 sec. 8) and the ocsp_multi
 * shape answers positionally, its list possibly shorter than the chain and possibly with an absent
 * element where no response is held (RFC 6961 sec. 2.2).
 */
public class SpreadCertificateStatusTest
    extends TestCase
{
    public void testOcspAnswersForTheEndEntityOnly()
    {
        CertificateStatus[] result = TlsUtils.spreadCertificateStatus(certificate(2),
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse("end-entity")));

        assertEquals(2, result.length);
        assertEquals("end-entity", markerOf(result[0]));
        assertNull("the rest of the chain is unanswered for", result[1]);
    }

    public void testOcspMultiAnswersPositionally()
    {
        CertificateStatus[] result = TlsUtils.spreadCertificateStatus(certificate(3),
            ocspMulti(new OCSPResponse[]{ ocspResponse("end-entity"), ocspResponse("intermediate"),
                ocspResponse("root") }));

        assertEquals(3, result.length);
        assertEquals("end-entity", markerOf(result[0]));
        assertEquals("intermediate", markerOf(result[1]));
        assertEquals("root", markerOf(result[2]));
    }

    /**
     * RFC 6961 sec. 2.2: the list "MAY be shorter than the number of certificates" - the certificates
     * it does not reach are simply unstapled.
     */
    public void testShortOcspMultiLeavesTheRestUnanswered()
    {
        CertificateStatus[] result = TlsUtils.spreadCertificateStatus(certificate(3),
            ocspMulti(new OCSPResponse[]{ ocspResponse("end-entity") }));

        assertEquals(3, result.length);
        assertEquals("end-entity", markerOf(result[0]));
        assertNull(result[1]);
        assertNull(result[2]);
    }

    /**
     * An absent element answers for nothing rather than being handed on as a status carrying no
     * response, which is what {@link CertificateStatus#getOCSPResponseList()} admits and what a
     * responder that holds a response for the end-entity but not its issuer produces.
     */
    public void testAbsentOcspMultiElementIsNotAStatus()
    {
        CertificateStatus[] result = TlsUtils.spreadCertificateStatus(certificate(2),
            ocspMulti(new OCSPResponse[]{ null, ocspResponse("intermediate") }));

        assertNull(result[0]);
        assertEquals("intermediate", markerOf(result[1]));
    }

    /**
     * More responses than there are certificates - which a BC server never sends, add13CertificateStatus
     * refusing to - must not read past the chain.
     */
    public void testLongOcspMultiIsTrimmedToTheChain()
    {
        CertificateStatus[] result = TlsUtils.spreadCertificateStatus(certificate(1),
            ocspMulti(new OCSPResponse[]{ ocspResponse("end-entity"), ocspResponse("intermediate") }));

        assertEquals(1, result.length);
        assertEquals("end-entity", markerOf(result[0]));
    }

    public void testNoStatusAnswersForNothing()
    {
        CertificateStatus[] result = TlsUtils.spreadCertificateStatus(certificate(2), null);

        assertEquals(2, result.length);
        assertNull(result[0]);
        assertNull(result[1]);
    }

    /**
     * A status where there is no chain to spread it over: the result is empty rather than an
     * exception, so that {@link TlsServerCertificate#getCertificateStatus()} reading element zero of
     * it has something to test.
     */
    public void testEmptyChainTakesNoStatus()
    {
        CertificateStatus[] result = TlsUtils.spreadCertificateStatus(certificate(0),
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse("end-entity")));

        assertEquals(0, result.length);
    }

    /**
     * Every status read out per certificate is a single response, whichever shape it arrived in - the
     * contract {@link TlsServerCertificate#getCertificateStatusAt(int)} states.
     */
    private static String markerOf(CertificateStatus certificateStatus)
    {
        assertEquals(CertificateStatusType.ocsp, certificateStatus.getStatusType());

        return Strings.fromByteArray(
            certificateStatus.getOCSPResponse().getResponseBytes().getResponse().getOctets());
    }

    private static Certificate certificate(int count)
    {
        CertificateEntry[] certificateEntryList = new CertificateEntry[count];
        for (int i = 0; i < count; ++i)
        {
            certificateEntryList[i] = new CertificateEntry(new StubTlsCertificate(), null);
        }

        return new Certificate(CertificateType.X509, TlsUtils.EMPTY_BYTES, certificateEntryList);
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

    /**
     * A response whose only distinguishing feature is the marker in its responseBytes: nothing here
     * looks inside one, so this is enough to tell which certificate got which.
     */
    private static OCSPResponse ocspResponse(String marker)
    {
        return new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL),
            new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic,
                new DEROctetString(Strings.toByteArray(marker))));
    }

    /**
     * spreadCertificateStatus only ever counts the certificates, so a stand-in keeps the test off the
     * crypto layer and its key material.
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
