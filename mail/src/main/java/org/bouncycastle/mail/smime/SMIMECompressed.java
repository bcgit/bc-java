package org.bouncycastle.mail.smime;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;

import org.bouncycastle.cms.CMSCompressedData;
import org.bouncycastle.cms.CMSException;

/**
 * containing class for an S/MIME pkcs7-mime MimePart.
 */
public class SMIMECompressed
    extends CMSCompressedData
{
    MimePart                message;

    public SMIMECompressed(
        MimeBodyPart    message) 
        throws MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message));

        this.message = message;
    }

    public SMIMECompressed(
        MimeMessage    message) 
        throws MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message));

        this.message = message;
    }

    public MimePart getCompressedContent()
    {
        return message;
    }
}
