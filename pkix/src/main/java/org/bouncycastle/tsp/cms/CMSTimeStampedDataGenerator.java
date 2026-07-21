package org.bouncycastle.tsp.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Evidence;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampTokenEvidence;
import org.bouncycastle.asn1.cms.TimeStampedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.io.Streams;

/**
 * Builder for an RFC 5544 TimeStampedData object. Given the initial RFC 3161 time
 * stamp token (computed over the message imprint of the document, and the MetaData
 * when it is hash-protected) plus the optional content set via the inherited
 * {@link #setDataUri}/{@link #setMetaData} methods, it produces a
 * {@link CMSTimeStampedData} whose evidence chain holds that one token.
 */
public class CMSTimeStampedDataGenerator
    extends CMSTimeStampedGenerator
{
    /**
     * Generate a TimeStampedData with no encapsulated content (e.g. when the document
     * is referenced via a dataUri).
     *
     * @param timeStamp the initial time stamp token.
     * @return the generated CMSTimeStampedData.
     * @throws CMSException if the structure cannot be built.
     */
    public CMSTimeStampedData generate(TimeStampToken timeStamp) throws CMSException
    {
        return generate(timeStamp, (InputStream)null);
    }

    /**
     * Generate a TimeStampedData encapsulating the passed in content.
     *
     * @param timeStamp the initial time stamp token.
     * @param content the document content to encapsulate.
     * @return the generated CMSTimeStampedData.
     * @throws CMSException if the structure cannot be built.
     */
    public CMSTimeStampedData generate(TimeStampToken timeStamp, byte[] content) throws CMSException
    {
        return generate(timeStamp, new ByteArrayInputStream(content));
    }

    /**
     * Generate a TimeStampedData encapsulating the content drained from the passed in
     * stream.
     *
     * @param timeStamp the initial time stamp token.
     * @param content a stream over the document content to encapsulate, or null for none.
     * @return the generated CMSTimeStampedData.
     * @throws CMSException if the content cannot be read or the structure cannot be built.
     */
    public CMSTimeStampedData generate(TimeStampToken timeStamp, InputStream content)
        throws CMSException
    {
        ASN1OctetString encContent = null;
        if (content != null)
        {
            ByteArrayOutputStream contentOut = new ByteArrayOutputStream();
            try
            {
                Streams.pipeAll(content, contentOut);
            }
            catch (IOException e)
            {
                throw new CMSException("exception encapsulating content: " + e.getMessage(), e);
            }

            if (contentOut.size() != 0)
            {
                encContent = new BEROctetString(contentOut.toByteArray());
            }
        }

        TimeStampAndCRL stamp = new TimeStampAndCRL(timeStamp.toCMSSignedData().toASN1Structure());

        ASN1IA5String asn1DataUri = null;

        if (dataUri != null)
        {
            asn1DataUri = new DERIA5String(dataUri.toString());
        }

        TimeStampedData timeStampedData = new TimeStampedData(asn1DataUri, metaData, encContent,
            new Evidence(new TimeStampTokenEvidence(stamp)));

        return new CMSTimeStampedData(new ContentInfo(CMSObjectIdentifiers.timestampedData, timeStampedData));
    }
}

