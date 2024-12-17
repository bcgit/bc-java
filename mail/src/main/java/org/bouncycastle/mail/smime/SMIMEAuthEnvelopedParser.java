package org.bouncycastle.mail.smime;

import org.bouncycastle.cms.CMSAuthEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;
import java.io.IOException;

/**
 * Stream based containing class for an S/MIME pkcs7-mime encrypted MimePart using AEAD algorithm.
 */
public class SMIMEAuthEnvelopedParser
    extends CMSAuthEnvelopedDataParser
{
    private final MimePart message;

    public SMIMEAuthEnvelopedParser(
        MimeBodyPart    message)
        throws IOException, MessagingException, CMSException
    {
        this(message, 0);
    }

    public SMIMEAuthEnvelopedParser(
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
    public SMIMEAuthEnvelopedParser(
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
     * @param bufferSize bufferSize to be used.
     */
    public SMIMEAuthEnvelopedParser(
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
