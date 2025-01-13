package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * General class for generating a pkcs7-mime message using AEAD algorithm.
 * <p>
 * A simple example of usage.
 *
 * <pre>
 *      SMIMEAuthEnvelopedGenerator fact = new SMIMEAuthEnvelopedGenerator();
 *
 *      fact.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
 *
 *      MimeBodyPart mp = fact.generate(content, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider("BC").build());
 * </pre>
 *
 * <b>Note:</b> Most clients expect the MimeBodyPart to be in a MimeMultipart
 * when it's sent.
 */
public class SMIMEAuthEnvelopedGenerator
    extends SMIMEEnvelopedGenerator
{
    public static final String AES128_GCM = CMSAuthEnvelopedDataGenerator.AES128_GCM;
    public static final String AES192_GCM = CMSAuthEnvelopedDataGenerator.AES192_GCM;
    public static final String AES256_GCM = CMSAuthEnvelopedDataGenerator.AES256_GCM;

    static final String AUTH_ENVELOPED_DATA_CONTENT_TYPE = "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=authEnveloped-data";

    final private AuthEnvelopedGenerator authFact;

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
    public SMIMEAuthEnvelopedGenerator()
    {
        authFact = new AuthEnvelopedGenerator();
    }

    /**
     * add a recipientInfoGenerator.
     */
    public void addRecipientInfoGenerator(
        RecipientInfoGenerator recipientInfoGen)
        throws IllegalArgumentException
    {
        authFact.addRecipientInfoGenerator(recipientInfoGen);
    }

    /**
     * Use a BER Set to store the recipient information
     */
    public void setBerEncodeRecipients(
        boolean berEncodeRecipientSet)
    {
        authFact.setBEREncodeRecipients(berEncodeRecipientSet);
    }

    /**
     * return encrypted content type for enveloped data.
     */
    protected String getEncryptedContentType()
    {
        return AUTH_ENVELOPED_DATA_CONTENT_TYPE;
    }

    /**
     * return content encryptor.
     */
    protected SMIMEStreamingProcessor getContentEncryptor(
        MimeBodyPart content,
        OutputEncryptor encryptor)
        throws SMIMEException
    {
        if (encryptor instanceof OutputAEADEncryptor)
        {
            return new ContentEncryptor(content, (OutputAEADEncryptor)encryptor);
        }
        // this would happen if the encryption algorithm is not AEAD algorithm
        throw new SMIMEException("encryptor is not AEAD encryptor");
    }

    private static class AuthEnvelopedGenerator
        extends CMSAuthEnvelopedDataStreamGenerator
    {
        private ASN1ObjectIdentifier dataType;
        private ASN1EncodableVector recipientInfos;

        protected OutputStream open(
            ASN1ObjectIdentifier dataType,
            OutputStream out,
            ASN1EncodableVector recipientInfos,
            OutputAEADEncryptor encryptor)
            throws IOException
        {
            this.dataType = dataType;
            this.recipientInfos = recipientInfos;

            return super.open(dataType, out, recipientInfos, encryptor);
        }

        OutputStream regenerate(
            OutputStream out,
            OutputAEADEncryptor encryptor)
            throws IOException
        {
            return super.open(dataType, out, recipientInfos, encryptor);
        }
    }

    private class ContentEncryptor
        implements SMIMEStreamingProcessor
    {
        private final MimeBodyPart _content;
        private OutputAEADEncryptor _encryptor;

        private boolean _firstTime = true;

        ContentEncryptor(
            MimeBodyPart content,
            OutputAEADEncryptor encryptor)
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
                    encrypted = authFact.open(out, _encryptor);

                    _firstTime = false;
                }
                else
                {
                    encrypted = authFact.regenerate(out, _encryptor);
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
}
