package org.bouncycastle.mail.smime;

import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSException;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;

/**
 * containing class for an S/MIME pkcs7-mime encrypted MimePart.
 */
public class SMIMEAuthEnveloped
    extends CMSAuthEnvelopedData
{
    MimePart                message;

    public SMIMEAuthEnveloped(
        MimeBodyPart    message)
        throws MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message));

        this.message = message;
    }

    public SMIMEAuthEnveloped(
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
