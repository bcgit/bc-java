package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.operator.InputExpander;
import org.bouncycastle.operator.InputExpanderProvider;
import org.bouncycastle.util.Encodable;

/**
 * containing class for an CMS Compressed Data object
 * <pre>
 *     CMSCompressedData cd = new CMSCompressedData(inputStream);
 *
 *     process(cd.getContent(new ZlibExpanderProvider()));
 * </pre>
 */
public class CMSCompressedData
    implements Encodable
{
    ContentInfo                 contentInfo;
    CompressedData              comData;

    /**
     * Create a CMSCompressedData object from its encoding.
     *
     * @param compressedData the complete encoding of the CompressedData structure (a CMS ContentInfo).
     *                       The array must hold the entire encoding and nothing extra - trailing bytes
     *                       beyond the CompressedData are not permitted.
     * @throws CMSException if the encoding cannot be parsed as a CompressedData.
     */
    public CMSCompressedData(
        byte[]    compressedData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    /**
     * Create a CMSCompressedData object from a stream.
     *
     * @param compressedData a stream positioned at the start of the CompressedData encoding (a CMS ContentInfo).
     * @throws CMSException if the encoding cannot be parsed as a CompressedData.
     */
    public CMSCompressedData(
        InputStream    compressedData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    /**
     * Create a CMSCompressedData object from an already-parsed ContentInfo.
     *
     * @param contentInfo the ContentInfo carrying the CompressedData.
     * @throws CMSException if the ContentInfo does not hold a well-formed CompressedData.
     */
    public CMSCompressedData(
        ContentInfo contentInfo)
        throws CMSException
    {
        this.contentInfo = contentInfo;

        ASN1Encodable content = contentInfo.getContent();
        if (content == null)
        {
            throw new CMSException("Missing content.");
        }

        try
        {
            this.comData = CompressedData.getInstance(content);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentInfo.getContentType();
    }

    public ASN1ObjectIdentifier getCompressedContentType()
    {
        return comData.getEncapContentInfo().getContentType();
    }

    public CMSTypedStream getContentStream(InputExpanderProvider expanderProvider)
        throws CMSException
    {
        ContentInfo     content = comData.getEncapContentInfo();

        ASN1OctetString bytes = getEncapsulatedContent(content);
        InputExpander   expander = expanderProvider.get(comData.getCompressionAlgorithmIdentifier());
        InputStream     zIn = expander.getInputStream(bytes.getOctetStream());

        return new CMSTypedStream(content.getContentType(), zIn);
    }

    /**
     * Return the uncompressed content.
     *
     * @param expanderProvider a provider of expander algorithm implementations.
     * @return the uncompressed content
     * @throws CMSException if there is an exception un-compressing the data.
     */
    public byte[] getContent(InputExpanderProvider expanderProvider)
        throws CMSException
    {
        ContentInfo     content = comData.getEncapContentInfo();

        ASN1OctetString bytes = getEncapsulatedContent(content);
        InputExpander   expander = expanderProvider.get(comData.getCompressionAlgorithmIdentifier());
        InputStream     zIn = expander.getInputStream(bytes.getOctetStream());

        try
        {
            return CMSUtils.streamToByteArray(zIn);
        }
        catch (IOException e)
        {
            throw new CMSException("exception reading compressed stream.", e);
        }
    }

    private static ASN1OctetString getEncapsulatedContent(ContentInfo content)
        throws CMSException
    {
        ASN1Encodable eContent = content.getContent();
        if (eContent == null)
        {
            throw new CMSException("Missing content.");
        }

        try
        {
            return ASN1OctetString.getInstance(eContent);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }
    
    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
}
