package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EncryptedData;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;

public class CMSEncryptedData
{
    private ContentInfo contentInfo;
    private EncryptedData encryptedData;

    /**
     * Create a CMSEncryptedData object from its encoding.
     *
     * @param encryptedData the complete encoding of the EncryptedData structure (a CMS ContentInfo).
     *                      The array must hold the entire encoding and nothing extra - trailing bytes
     *                      beyond the EncryptedData are not permitted.
     * @throws CMSException if the encoding cannot be parsed as an EncryptedData.
     */
    public CMSEncryptedData(byte[] encryptedData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(encryptedData));
    }

    /**
     * Create a CMSEncryptedData object from a stream.
     *
     * @param encryptedData a stream positioned at the start of the EncryptedData encoding (a CMS ContentInfo).
     * @throws CMSException if the encoding cannot be parsed as an EncryptedData.
     */
    public CMSEncryptedData(InputStream encryptedData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(encryptedData));
    }

    /**
     * Create a CMSEncryptedData object from an already-parsed ContentInfo.
     * <p>
     * Note: unlike the sibling CMS container constructors this one is not declared to throw
     * CMSException; malformed inner content surfaces as an IllegalArgumentException.
     *
     * @param contentInfo the ContentInfo carrying the EncryptedData.
     */
    public CMSEncryptedData(ContentInfo contentInfo)
    {
        this.contentInfo = contentInfo;

        // NOTE: unlike the sibling CMS container constructors (CMSSignedData, CMSEnvelopedData,
        // CMSCompressedData, CMSDigestedData, CMSAuthEnvelopedData, CMSAuthenticatedData) this
        // constructor is not declared to throw CMSException, so the inner EncryptedData.getInstance
        // is left unguarded here: a malformed inner content surfaces as a raw IllegalArgumentException
        // rather than CMSException("Malformed content.") / ("Missing content."). The only
        // untrusted-bytes reach is PKCS12SafeBagFactory(ContentInfo, InputDecryptorProvider) (declared
        // throws PKCSException), whose javadoc already declares IllegalArgumentException for the
        // content-type check.
        this.encryptedData = EncryptedData.getInstance(contentInfo.getContent());
    }

    public byte[] getContent(InputDecryptorProvider inputDecryptorProvider)
        throws CMSException
    {
        try
        {
            return CMSUtils.streamToByteArray(getContentStream(inputDecryptorProvider).getContentStream());
        }
        catch (IOException e)
        {
            throw new CMSException("unable to parse internal stream: " + e.getMessage(), e);
        }
    }

    public CMSTypedStream getContentStream(InputDecryptorProvider inputDecryptorProvider)
        throws CMSException
    {
        try
        {
            EncryptedContentInfo encContentInfo = encryptedData.getEncryptedContentInfo();
            InputDecryptor decrytor = inputDecryptorProvider.get(encContentInfo.getContentEncryptionAlgorithm());

            ByteArrayInputStream encIn = new ByteArrayInputStream(encContentInfo.getEncryptedContent().getOctets());

            return new CMSTypedStream(encContentInfo.getContentType(), decrytor.getInputStream(encIn));
        }
        catch (Exception e)
        {
            throw new CMSException("unable to create stream: " + e.getMessage(), e);
        }
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }
}
