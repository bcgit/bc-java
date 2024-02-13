package org.bouncycastle.mail.smime;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;

import org.bouncycastle.cms.CMSCompressedDataParser;
import org.bouncycastle.cms.CMSException;

/**
 * Stream based containing class for an S/MIME pkcs7-mime compressed MimePart.
 */
public class SMIMECompressedParser
    extends CMSCompressedDataParser
{
    private final MimePart message;

    public SMIMECompressedParser(
        MimeBodyPart    message) 
        throws MessagingException, CMSException
    {
        this(message, 0);
    }

    public SMIMECompressedParser(
        MimeMessage    message) 
        throws MessagingException, CMSException
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
    public SMIMECompressedParser(
        MimeBodyPart    message,
        int             bufferSize) 
        throws MessagingException, CMSException
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
    public SMIMECompressedParser(
        MimeMessage    message,
        int            bufferSize) 
        throws MessagingException, CMSException
    {
        super(SMIMEUtil.getInputStream(message, bufferSize));

        this.message = message;
    }

    public MimePart getCompressedContent()
    {
        return message;
    }
}
