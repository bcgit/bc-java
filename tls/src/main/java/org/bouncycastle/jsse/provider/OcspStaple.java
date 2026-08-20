package org.bouncycastle.jsse.provider;

import java.util.Date;

import org.bouncycastle.asn1.ocsp.OCSPResponse;

/**
 * An OCSP response held for stapling, together with the validity interval the responder stated for
 * the certificate it answers about.
 * <p/>
 * The response is carried verbatim as it arrived from the responder; it is <b>not</b> validated
 * here. A stapling server is a relay - RFC 6066 sec. 8 has it pass the responder's answer through to
 * the client, and the client is the party that verifies the responder's signature and decides what
 * the answer means. The times are extracted only so that {@link OcspStapleCache} can tell how long
 * the response may be reused, which is a caching question rather than a trust one.
 */
final class OcspStaple
{
    private final OCSPResponse response;
    private final Date thisUpdate;
    private final Date nextUpdate;

    /**
     * @param response   the response as received from the responder.
     * @param thisUpdate the thisUpdate of the SingleResponse answering for the certificate.
     * @param nextUpdate the nextUpdate of that SingleResponse, or null if it stated none.
     */
    OcspStaple(OCSPResponse response, Date thisUpdate, Date nextUpdate)
    {
        this.response = response;
        this.thisUpdate = copy(thisUpdate);
        this.nextUpdate = copy(nextUpdate);
    }

    OCSPResponse getResponse()
    {
        return response;
    }

    Date getThisUpdate()
    {
        return copy(thisUpdate);
    }

    /**
     * @return the stated nextUpdate, or null if the responder stated none. RFC 6960 sec. 4.2.2.1
     *         reads an absent nextUpdate as "newer revocation information is available all the
     *         time", so a response without one is never reused from the cache.
     */
    Date getNextUpdate()
    {
        return copy(nextUpdate);
    }

    private static Date copy(Date date)
    {
        return null == date ? null : new Date(date.getTime());
    }
}
