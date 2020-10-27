package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * General class for generating a pkcs7-mime message.
 *
 * A simple example of usage.
 *
 * <pre>
 *      SMIMEEnvelopedGenerator  fact = new SMIMEEnvelopedGenerator();
 *
 *      fact.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
 *
 *      MimeBodyPart mp = fact.generate(content, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider("BC").build());
 * </pre>
 *
 * <b>Note:</b> Most clients expect the MimeBodyPart to be in a MimeMultipart
 * when it's sent.
 */
public class SMIMEEnvelopedGenerator
    extends SMIMEGenerator
{
    public static final String  DES_EDE3_CBC    = CMSEnvelopedDataGenerator.DES_EDE3_CBC;
    public static final String  RC2_CBC         = CMSEnvelopedDataGenerator.RC2_CBC;
    public static final String  IDEA_CBC        = CMSEnvelopedDataGenerator.IDEA_CBC;
    public static final String  CAST5_CBC       = CMSEnvelopedDataGenerator.CAST5_CBC;

    public static final String  AES128_CBC      = CMSEnvelopedDataGenerator.AES128_CBC;
    public static final String  AES192_CBC      = CMSEnvelopedDataGenerator.AES192_CBC;
    public static final String  AES256_CBC      = CMSEnvelopedDataGenerator.AES256_CBC;

    public static final String  CAMELLIA128_CBC = CMSEnvelopedDataGenerator.CAMELLIA128_CBC;
    public static final String  CAMELLIA192_CBC = CMSEnvelopedDataGenerator.CAMELLIA192_CBC;
    public static final String  CAMELLIA256_CBC = CMSEnvelopedDataGenerator.CAMELLIA256_CBC;

    public static final String  SEED_CBC        = CMSEnvelopedDataGenerator.SEED_CBC;

    public static final String  DES_EDE3_WRAP   = CMSEnvelopedDataGenerator.DES_EDE3_WRAP;
    public static final String  AES128_WRAP     = CMSEnvelopedDataGenerator.AES128_WRAP;
    public static final String  AES256_WRAP     = CMSEnvelopedDataGenerator.AES256_WRAP;
    public static final String  CAMELLIA128_WRAP = CMSEnvelopedDataGenerator.CAMELLIA128_WRAP;
    public static final String  CAMELLIA192_WRAP = CMSEnvelopedDataGenerator.CAMELLIA192_WRAP;
    public static final String  CAMELLIA256_WRAP = CMSEnvelopedDataGenerator.CAMELLIA256_WRAP;
    public static final String  SEED_WRAP       = CMSEnvelopedDataGenerator.SEED_WRAP;
    
    public static final String  ECDH_SHA1KDF    = CMSEnvelopedDataGenerator.ECDH_SHA1KDF;

    private static final String ENCRYPTED_CONTENT_TYPE = "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data";
    
    private EnvelopedGenerator fact;

    static
    {
        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                CommandMap commandMap = CommandMap.getDefaultCommandMap();

                if (commandMap instanceof MailcapCommandMap)
                {
                    CommandMap.setDefaultCommandMap(MailcapUtil.addCommands((MailcapCommandMap)commandMap));
                }

                return null;
            }
        });
    }

    /**
     * base constructor
     */
    public SMIMEEnvelopedGenerator()
    {
        fact = new EnvelopedGenerator();
    }

    /**
     * add a recipientInfoGenerator.
     */
    public void addRecipientInfoGenerator(
        RecipientInfoGenerator recipientInfoGen)
        throws IllegalArgumentException
    {
        fact.addRecipientInfoGenerator(recipientInfoGen);
    }

    /**
     * Use a BER Set to store the recipient information
     */
    public void setBerEncodeRecipients(
        boolean berEncodeRecipientSet)
    {
        fact.setBEREncodeRecipients(berEncodeRecipientSet);
    }

     /**
     * if we get here we expect the Mime body part to be well defined.
     */
    private MimeBodyPart make(
        MimeBodyPart    content,
        OutputEncryptor encryptor)
        throws SMIMEException
    {
        try
        {
            MimeBodyPart data = new MimeBodyPart();

            data.setContent(new ContentEncryptor(content, encryptor), ENCRYPTED_CONTENT_TYPE);
            data.addHeader("Content-Type", ENCRYPTED_CONTENT_TYPE);
            data.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
            data.addHeader("Content-Description", "S/MIME Encrypted Message");
            data.addHeader("Content-Transfer-Encoding", encoding);

            return data;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting multi-part together.", e);
        }
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given content encryptor
     */
    public MimeBodyPart generate(
        MimeBodyPart     content,
        OutputEncryptor  encryptor)
        throws SMIMEException
    {
        return make(makeContentBodyPart(content), encryptor);
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider from the contents of the passed in
     * message
     */
    public MimeBodyPart generate(
        MimeMessage     message,
        OutputEncryptor  encryptor)
        throws SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }

        return make(makeContentBodyPart(message), encryptor);
    }

    private class ContentEncryptor
        implements SMIMEStreamingProcessor
    {
        private final MimeBodyPart _content;
        private OutputEncryptor _encryptor;

        private boolean _firstTime = true;

        ContentEncryptor(
            MimeBodyPart content,
            OutputEncryptor encryptor)
        {
            _content = content;
            _encryptor = encryptor;
        }

        public void write(OutputStream out)
            throws IOException
        {
            OutputStream encrypted;

            try
            {
                if (_firstTime)
                {
                    encrypted = fact.open(out, _encryptor);

                    _firstTime = false;
                }
                else
                {
                    encrypted = fact.regenerate(out, _encryptor);
                }

                CommandMap commandMap = CommandMap.getDefaultCommandMap();

                if (commandMap instanceof MailcapCommandMap)
                {
                    _content.getDataHandler().setCommandMap(MailcapUtil.addCommands((MailcapCommandMap)commandMap));
                }

                _content.writeTo(encrypted);

                encrypted.close();
            }
            catch (MessagingException e)
            {
                throw new WrappingIOException(e.toString(), e);
            }
            catch (CMSException e)
            {
                throw new WrappingIOException(e.toString(), e);
            }
        }
    }

    private class EnvelopedGenerator
        extends CMSEnvelopedDataStreamGenerator
    {
        private ASN1ObjectIdentifier dataType;
        private ASN1EncodableVector  recipientInfos;

        protected OutputStream open(
            ASN1ObjectIdentifier dataType,
            OutputStream         out,
            ASN1EncodableVector  recipientInfos,
            OutputEncryptor      encryptor)
            throws IOException
        {
            this.dataType = dataType;
            this.recipientInfos = recipientInfos;

            return super.open(dataType, out, recipientInfos, encryptor);
        }

        OutputStream regenerate(
            OutputStream out,
            OutputEncryptor     encryptor)
            throws IOException
        {
            return super.open(dataType, out, recipientInfos, encryptor);
        }
    }

    private static class WrappingIOException
        extends IOException
    {
        private Throwable cause;

        WrappingIOException(String msg, Throwable cause)
        {
            super(msg);

            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }
}
