package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.DigestedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;

/**
 * containing class for an CMS Digested Data object
 * <pre>
 *     CMSDigestedData cd = new CMSDigestedData(inputStream);
 *
 *
 *     process(cd.getContent());
 * </pre>
 */
public class CMSDigestedData
    implements Encodable
{
    private ContentInfo  contentInfo;
    private DigestedData digestedData;

    public CMSDigestedData(
        byte[] compressedData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSDigestedData(
        InputStream compressedData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSDigestedData(
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
            this.digestedData = DigestedData.getInstance(content);
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

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestedData.getDigestAlgorithm();
    }

    /**
     * Return the digested content
     *
     * @return the digested content
     * @throws CMSException if there is an exception un-compressing the data.
     */
    public CMSProcessable getDigestedContent()
        throws CMSException
    {
        ContentInfo     content = digestedData.getEncapContentInfo();
        ASN1OctetString bytes = getEncapsulatedContent(content);

        return new CMSProcessableByteArray(content.getContentType(), bytes.getOctets());
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

    public boolean verify(DigestCalculatorProvider calculatorProvider)
        throws CMSException
    {
        ContentInfo     content = digestedData.getEncapContentInfo();
        ASN1OctetString bytes = getEncapsulatedContent(content);

        try
        {
            DigestCalculator calc = calculatorProvider.get(digestedData.getDigestAlgorithm());

            OutputStream dOut = calc.getOutputStream();

            dOut.write(bytes.getOctets());

            return Arrays.areEqual(digestedData.getDigest(), calc.getDigest());
        }
        catch (OperatorCreationException e)
        {
            throw new CMSException("unable to create digest calculator: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new CMSException("unable process content: " + e.getMessage(), e);
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
}
