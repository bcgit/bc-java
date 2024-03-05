package org.bouncycastle.mail.smime;

import java.io.IOException;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;

import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;

/**
 * Stream based containing class for an S/MIME pkcs7-mime encrypted MimePart.
 */
public class SMIMEEnvelopedParser
    extends CMSEnvelopedDataParser
{
    private final MimePart message;

    public SMIMEEnvelopedParser(
        MimeBodyPart    message) 
        throws IOException, MessagingException, CMSException
    {
        this(message, 0);
    }

    public SMIMEEnvelopedParser(
        MimeMessage    message) 
        throws IOException, MessagingException, CMSException
    {
        this(message, 0);
    }
    
    /**
     * Create a parser from a MimeBodyPart using the passed in buffer size
     * for reading it.
     * 
     * @param message body part to be parsed.
     * @param bufferSize bufferSoze to be used.
     */
    public SMIMEEnvelopedParser(
        MimeBodyPart    message,
        int             bufferSize) 
        throws IOException, MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message, bufferSize));

        this.message = message;
    }

    /**
     * Create a parser from a MimeMessage using the passed in buffer size
     * for reading it.
     * 
     * @param message message to be parsed.
     * @param bufferSize bufferSoze to be used.
     */
    public SMIMEEnvelopedParser(
        MimeMessage    message,
        int            bufferSize) 
        throws IOException, MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message, bufferSize));

        this.message = message;
    }

    public MimePart getEncryptedContent()
    {
        return message;
    }
}
