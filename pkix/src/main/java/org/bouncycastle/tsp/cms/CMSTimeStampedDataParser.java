package org.bouncycastle.tsp.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.TimeStampedDataParser;
import org.bouncycastle.cms.CMSContentInfoParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.io.Streams;

/**
 * Streaming parser for an RFC 5544 TimeStampedData object. It exposes the dataUri,
 * MetaData and (streamed) content of the time-stamped document together with the
 * Evidence chain of RFC 3161 time stamp tokens, reading from the supplied stream
 * lazily rather than buffering the whole structure as {@link CMSTimeStampedData} does.
 * <p>
 * The encapsulated content is drained from {@link #getContent()} before the trailing
 * evidence block can be parsed; the methods that need the time stamps
 * ({@link #getTimeStampTokens()}, {@link #getMessageImprintDigestCalculator}, the
 * {@code validate} methods) drain it automatically. The supplied InputStream is closed
 * only when {@link #close()} (inherited from {@link CMSContentInfoParser}) is invoked.
 * </p>
 */
public class CMSTimeStampedDataParser
    extends CMSContentInfoParser
{
    private TimeStampedDataParser timeStampedData;
    private TimeStampDataUtil util;

    public CMSTimeStampedDataParser(InputStream in)
        throws CMSException
    {
        super(in);

        initialize(_contentInfo);
    }

    public CMSTimeStampedDataParser(byte[] baseData)
        throws CMSException
    {
        this(new ByteArrayInputStream(baseData));
    }

    private void initialize(ContentInfoParser contentInfo)
        throws CMSException
    {
        try
        {
            if (CMSObjectIdentifiers.timestampedData.equals(contentInfo.getContentType()))
            {
                this.timeStampedData = TimeStampedDataParser.getInstance(contentInfo.getContent(BERTags.SEQUENCE));
            }
            else
            {
                throw new IllegalArgumentException("Malformed content - type must be " + CMSObjectIdentifiers.timestampedData.getId());
            }
        }
        catch (IOException e)
        {
            throw new CMSException("parsing exception: " + e.getMessage(), e);
        }
    }

    /**
     * Calculate the hash over the last time stamp element in the evidence chain, as
     * required to obtain the next time stamp token that extends the chain (per RFC 5544
     * each token is computed over its preceding element).
     *
     * @param calculator the digest calculator to use.
     * @return the digest of the DER encoding of the most recent TimeStampAndCRL.
     * @throws CMSException if the hash cannot be calculated.
     */
    public byte[] calculateNextHash(DigestCalculator calculator)
        throws CMSException
    {
        return util.calculateNextHash(calculator);
    }

    /**
     * Return a stream over the encapsulated content, if present. The stream must be
     * drained before the trailing evidence block can be parsed.
     *
     * @return an InputStream over the content octets, or null if no content is carried.
     */
    public InputStream getContent()
    {
        if (timeStampedData.getContent() != null)
        {
            return timeStampedData.getContent().getOctetStream();
        }

        return null;
    }

    /**
     * Return the dataUri referencing the time-stamped document, if present.
     *
     * @return the dataUri, or null if none was set.
     * @throws URISyntaxException if the stored value is not a valid URI.
     */
    public URI getDataUri()
        throws URISyntaxException
    {
        ASN1IA5String dataURI = this.timeStampedData.getDataUriIA5();

        if (dataURI != null)
        {
           return new URI(dataURI.getString());
        }

        return null;
    }

    public String getFileName()
    {
        return util.getFileName();
    }

    public String getMediaType()
    {
        return util.getMediaType();
    }

    public AttributeTable getOtherMetaData()
    {
        return util.getOtherMetaData();
    }

    /**
     * Initialise the passed in calculator with the MetaData for this message, if it is
     * required as part of the initial message imprint calculation.
     *
     * @param calculator the digest calculator to be initialised.
     * @throws CMSException if the MetaData is required and cannot be processed
     */
    public void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
        throws CMSException
    {
        util.initialiseMessageImprintDigestCalculator(calculator);
    }

    /**
     * Returns an appropriately initialised digest calculator based on the message imprint algorithm
     * described in the first time stamp in the TemporalData for this message. If the metadata is required
     * to be included in the digest calculation, the returned calculator will be pre-initialised.
     *
     * @param calculatorProvider  a provider of DigestCalculator objects.
     * @return an initialised digest calculator.
     * @throws OperatorCreationException if the provider is unable to create the calculator.
     */
    public DigestCalculator getMessageImprintDigestCalculator(DigestCalculatorProvider calculatorProvider)
        throws OperatorCreationException
    {
        try
        {
            parseTimeStamps();
        }
        catch (CMSException e)
        {
            throw new OperatorCreationException("unable to extract algorithm ID: " + e.getMessage(), e);
        }

        return util.getMessageImprintDigestCalculator(calculatorProvider);
    }

    /**
     * Return the time stamp tokens making up the evidence chain, in order. The
     * encapsulated content is drained first if it has not already been read.
     *
     * @return an array of the time stamp tokens present in the message.
     * @throws CMSException if the evidence block cannot be parsed.
     */
    public TimeStampToken[] getTimeStampTokens()
        throws CMSException
    {
        parseTimeStamps();

        return util.getTimeStampTokens();
    }

    /**
     * Validate the digests present in the TimeStampTokens contained in the CMSTimeStampedData.
     *
     * @param calculatorProvider provider for digest calculators
     * @param dataDigest the calculated data digest for the message
     * @throws ImprintDigestInvalidException if an imprint digest fails to compare
     * @throws CMSException  if an exception occurs processing the message.
     */
    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest)
        throws ImprintDigestInvalidException, CMSException
    {
        parseTimeStamps();

        util.validate(calculatorProvider, dataDigest);
    }

    /**
     * Validate the passed in timestamp token against the tokens and data present in the message.
     *
     * @param calculatorProvider provider for digest calculators
     * @param dataDigest the calculated data digest for the message.
     * @param timeStampToken  the timestamp token of interest.
     * @throws ImprintDigestInvalidException if the token is not present in the message, or an imprint digest fails to compare.
     * @throws CMSException if an exception occurs processing the message.
     */
    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest, TimeStampToken timeStampToken)
        throws ImprintDigestInvalidException, CMSException
    {
        parseTimeStamps();

        util.validate(calculatorProvider, dataDigest, timeStampToken);
    }

    private void parseTimeStamps()
        throws CMSException
    {
        try
        {
            if (util == null)
            {
                InputStream cont = this.getContent();

                if (cont != null)
                {
                    Streams.drain(cont);
                }

                util = new TimeStampDataUtil(timeStampedData);
            }
        }
        catch (IOException e)
        {
            throw new CMSException("unable to parse evidence block: " + e.getMessage(), e);
        }
    }
}
