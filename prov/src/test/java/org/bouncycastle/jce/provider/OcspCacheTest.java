package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.io.StreamOverflowException;

/**
 * Lives in the {@code org.bouncycastle.jce.provider} package so it can call the package-private
 * {@link OcspCache#getResponseSizeLimit} directly. The responder's Content-Length may narrow how
 * much of an OCSP response is read but must never widen it past our own ceiling.
 */
public class OcspCacheTest
    extends TestCase
{
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024;

    public String getName()
    {
        return "OcspCache";
    }

    public void testDefaultCeiling()
    {
        // a declared length beyond the ceiling is capped, not trusted
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(100 * 1024 * 1024));
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(Integer.MAX_VALUE));

        // absent Content-Length falls back to the ceiling, as it always did
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(-1));

        // a declared length within the ceiling still narrows the read
        assertEquals(0, OcspCache.getResponseSizeLimit(0));
        assertEquals(1024, OcspCache.getResponseSizeLimit(1024));
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(DEFAULT_MAX_RESPONSE_SIZE));
    }

    public void testConfiguredCeiling()
    {
        System.setProperty(Properties.OCSP_MAX_RESPONSE_SIZE, "4096");
        try
        {
            assertEquals(4096, OcspCache.getResponseSizeLimit(100 * 1024 * 1024));
            assertEquals(4096, OcspCache.getResponseSizeLimit(-1));
            assertEquals(100, OcspCache.getResponseSizeLimit(100));
        }
        finally
        {
            System.getProperties().remove(Properties.OCSP_MAX_RESPONSE_SIZE);
        }

        // a value that cannot be a size leaves the default in place rather than lifting the limit
        String[] unusable = new String[]{ "0", "-1" };
        for (int i = 0; i != unusable.length; i++)
        {
            System.setProperty(Properties.OCSP_MAX_RESPONSE_SIZE, unusable[i]);
            try
            {
                assertEquals("\"" + unusable[i] + "\" did not fall back to the default ceiling",
                    DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(100 * 1024 * 1024));
            }
            finally
            {
                System.getProperties().remove(Properties.OCSP_MAX_RESPONSE_SIZE);
            }
        }
    }

    public void testOverLongResponseNamesTheLimit()
        throws Exception
    {
        byte[] tooMuch = new byte[100 * 1024];

        try
        {
            OcspCache.readResponse(new ByteArrayInputStream(tooMuch), 1024);
            fail("over-long OCSP response accepted");
        }
        catch (StreamOverflowException e)
        {
            // "Data Overflow" on its own says nothing about what was read or what to change
            assertEquals("OCSP response exceeds 1024 bytes (see org.bouncycastle.ocsp.max_response_size)",
                e.getMessage());
        }

        // a response within the limit is returned as it stands
        byte[] response = new byte[]{ 0x30, 0x03, 0x0a, 0x01, 0x00 };

        assertTrue(Arrays.areEqual(response, OcspCache.readResponse(new ByteArrayInputStream(response), 1024)));
    }
    /**
     * A cached response is only reusable while it states a validity interval covering the time
     * being validated for. RFC 6960 sec. 4.2.2.1: "if nextUpdate is not set, the responder is
     * indicating that newer revocation information is available all the time" - so there is no
     * interval to reuse it over, and the cache must go back to the responder.
     */
    public void testResponseWithoutNextUpdateIsNeverCurrent()
        throws Exception
    {
        Date now = new Date();
        CertID certID = certID();

        BasicOCSPResponse withNextUpdate = response(certID, minutesFromNow(now, -5), minutesFromNow(now, 60));
        assertTrue("response inside its own validity interval was not current",
            OcspCache.isCertIDFoundAndCurrent(withNextUpdate, now, certID));

        BasicOCSPResponse expired = response(certID, minutesFromNow(now, -120), minutesFromNow(now, -60));
        assertFalse("expired response was current", OcspCache.isCertIDFoundAndCurrent(expired, now, certID));

        BasicOCSPResponse noNextUpdate = response(certID, minutesFromNow(now, -5), null);
        assertFalse("response with no nextUpdate was reused from the cache",
            OcspCache.isCertIDFoundAndReusable(noNextUpdate, now, certID));

        // however old it is
        BasicOCSPResponse ancient = response(certID, minutesFromNow(now, -60 * 24 * 365), null);
        assertFalse("year-old response with no nextUpdate was reused from the cache",
            OcspCache.isCertIDFoundAndReusable(ancient, now, certID));

        // but nothing is rejected by that: a responder is entitled not to state a nextUpdate, and
        // the response it just gave us is used for the check it arrived for
        assertTrue("freshly fetched response with no nextUpdate was refused",
            OcspCache.isCertIDFoundAndCurrent(noNextUpdate, now, certID));

        // the interval is still honoured where one is stated
        assertTrue("response inside its validity interval was not reusable",
            OcspCache.isCertIDFoundAndReusable(withNextUpdate, now, certID));
        assertFalse("expired response was reusable", OcspCache.isCertIDFoundAndReusable(expired, now, certID));
    }

    /**
     * "Responses whose thisUpdate time is later than the local system time SHOULD be considered
     * unreliable" - RFC 6960 sec. 4.2.2.1. Clock skew between us and the responder is allowed for.
     */
    public void testResponseDatedInTheFuture()
        throws Exception
    {
        Date now = new Date();
        CertID certID = certID();

        BasicOCSPResponse withinSkew = response(certID, minutesFromNow(now, 5), minutesFromNow(now, 60));
        assertTrue("response inside the clock skew allowance was rejected",
            OcspCache.isCertIDFoundAndCurrent(withinSkew, now, certID));

        BasicOCSPResponse fromTheFuture = response(certID, minutesFromNow(now, 60), minutesFromNow(now, 120));
        assertFalse("response dated an hour ahead was current",
            OcspCache.isCertIDFoundAndCurrent(fromTheFuture, now, certID));

        assertFalse("absent thisUpdate treated as future", OcspCache.isFromTheFuture(null, now));
    }

    private static ASN1GeneralizedTime minutesFromNow(Date now, int minutes)
    {
        return new ASN1GeneralizedTime(new Date(now.getTime() + (minutes * 60 * 1000L)));
    }

    private static CertID certID()
    {
        return new CertID(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            new DEROctetString(new byte[32]), new DEROctetString(new byte[32]), new ASN1Integer(BigInteger.ONE));
    }

    private static BasicOCSPResponse response(CertID certID, ASN1GeneralizedTime thisUpdate,
        ASN1GeneralizedTime nextUpdate)
    {
        SingleResponse single = new SingleResponse(certID, new CertStatus(), thisUpdate, nextUpdate,
            (Extensions)null);

        ResponseData responseData = new ResponseData(new ResponderID(new X500Name("CN=Test Responder")),
            thisUpdate, new DERSequence(single), (Extensions)null);

        return new BasicOCSPResponse(responseData, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            new DERBitString(new byte[]{ 1 }), (ASN1Sequence)null);
    }
}
