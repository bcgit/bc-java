package org.bouncycastle.mail.smime;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;

/**
 * containing class for an S/MIME pkcs7-mime encrypted MimePart.
 */
public class SMIMEEnveloped
    extends CMSEnvelopedData
{
    MimePart                message;

    public SMIMEEnveloped(
        MimeBodyPart    message) 
        throws MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message));

        this.message = message;
    }

    public SMIMEEnveloped(
        MimeMessage    message) 
        throws MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message));

        this.message = message;
    }

    public MimePart getEncryptedContent()
    {
        return message;
    }
}
