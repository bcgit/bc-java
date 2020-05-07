package org.bouncycastle.mail.smime;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.operator.DigestCalculatorProvider;

/**
 * general class for handling a pkcs7-signature message.
 * <p>
 * A simple example of usage - note, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs 
 * matches the given signer...
 * <p>
 * <pre>
 *  CertStore               certs = s.getCertificates("Collection", "BC");
 *  SignerInformationStore  signers = s.getSignerInfos();
 *  Collection              c = signers.getSigners();
 *  Iterator                it = c.iterator();
 *  
 *  while (it.hasNext())
 *  {
 *      SignerInformation   signer = (SignerInformation)it.next();
 *      Collection          certCollection = certs.getCertificates(signer.getSID());
 *  
 *      Iterator        certIt = certCollection.iterator();
 *      X509Certificate cert = (X509Certificate)certIt.next();
 *  
 *      if (signer.verify(cert.getPublicKey()))
 *      {
 *          verified++;
 *      }   
 *  }
 * </pre>
 * <p>
 * Note: if you are using this class with AS2 or some other protocol
 * that does not use 7bit as the default content transfer encoding you
 * will need to use the constructor that allows you to specify the default
 * content transfer encoding, such as "binary".
 * </p>
 */
public class SMIMESignedParser
    extends CMSSignedDataParser
{
    Object                  message;
    MimeBodyPart            content;

    private static InputStream getInputStream(
        Part    bodyPart)
        throws MessagingException
    {
        try
        {
            if (bodyPart.isMimeType("multipart/signed"))
            {
                throw new MessagingException("attempt to create signed data object from multipart content - use MimeMultipart constructor.");
            }
            
            return bodyPart.getInputStream();
        }
        catch (IOException e)
        {
            throw new MessagingException("can't extract input stream: " + e);
        }
    }

    private static File getTmpFile()
        throws MessagingException
    {
        try
        {
            return File.createTempFile("bcMail", ".mime");
        }
        catch (IOException e)
        {
            throw new MessagingException("can't extract input stream: " + e);
        }
    }

    private static CMSTypedStream getSignedInputStream(
        BodyPart    bodyPart,
        String      defaultContentTransferEncoding,
        File        backingFile)
        throws MessagingException
    {
        try
        {
            OutputStream   out = new BufferedOutputStream(new FileOutputStream(backingFile));

            SMIMEUtil.outputBodyPart(out, true, bodyPart, defaultContentTransferEncoding);

            out.close();

            InputStream in = new TemporaryFileInputStream(backingFile);

            return new CMSTypedStream(in);
        }
        catch (IOException e)
        {
            throw new MessagingException("can't extract input stream: " + e);
        }
    }

    /**
     * base constructor using a defaultContentTransferEncoding of 7bit. A temporary backing file
     * will be created for the signed data.
     *
     * @param digCalcProvider provider for digest calculators.
     * @param message signed message with signature.
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception CMSException if some other problem occurs.
     */
    public SMIMESignedParser(
        DigestCalculatorProvider digCalcProvider,
        MimeMultipart message)
        throws MessagingException, CMSException
    {
        this(digCalcProvider, message, getTmpFile());
    }

    /**
     * base constructor using a defaultContentTransferEncoding of 7bit and a specified backing file.
     *
     * @param digCalcProvider provider for digest calculators.
     * @param message signed message with signature.
     * @param backingFile the temporary file to use to back the signed data.
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception CMSException if some other problem occurs.
     */
    public SMIMESignedParser(
        DigestCalculatorProvider digCalcProvider,
        MimeMultipart message,
        File          backingFile)
        throws MessagingException, CMSException
    {
        this(digCalcProvider, message, "7bit", backingFile);
    }

    /**
     * base constructor with settable contentTransferEncoding. A temporary backing file will be created
     * to contain the signed data.
     *
     * @param digCalcProvider provider for digest calculators.
     * @param message the signed message with signature.
     * @param defaultContentTransferEncoding new default to use.
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception CMSException if some other problem occurs.r
     */
    public SMIMESignedParser(
        DigestCalculatorProvider digCalcProvider,
        MimeMultipart message,
        String        defaultContentTransferEncoding)
        throws MessagingException, CMSException
    {
        this(digCalcProvider, message, defaultContentTransferEncoding, getTmpFile());
    }

    /**
     * base constructor with settable contentTransferEncoding and a specified backing file.
     *
     * @param digCalcProvider provider for digest calculators.
     * @param message the signed message with signature.
     * @param defaultContentTransferEncoding new default to use.
     * @param backingFile the temporary file to use to back the signed data.
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception CMSException if some other problem occurs.
     */
    public SMIMESignedParser(
        DigestCalculatorProvider digCalcProvider,
        MimeMultipart message,
        String        defaultContentTransferEncoding,
        File          backingFile)
        throws MessagingException, CMSException
    {
        super(digCalcProvider, getSignedInputStream(message.getBodyPart(0), defaultContentTransferEncoding, backingFile), getInputStream(message.getBodyPart(1)));

        this.message = message;
        this.content = (MimeBodyPart)message.getBodyPart(0);

        drainContent();
    }

    /**
     * base constructor for a signed message with encapsulated content.
     * <p>
     * Note: in this case the encapsulated MimeBody part will only be suitable for a single
     * writeTo - once writeTo has been called the file containing the body part will be deleted. If writeTo is not
     * called the file will be left in the temp directory.
     * </p>
     * @param digCalcProvider provider for digest calculators.
     * @param message the message containing the encapsulated signed data.
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception SMIMEException if the body part encapsulated in the message cannot be extracted.
     * @exception CMSException if some other problem occurs.
     */
    public SMIMESignedParser(
        DigestCalculatorProvider digCalcProvider,
        Part message)
        throws MessagingException, CMSException, SMIMEException
    {
        super(digCalcProvider, getInputStream(message));

        this.message = message;

        CMSTypedStream  cont = this.getSignedContent();

        if (cont != null)
        {
            this.content = SMIMEUtil.toWriteOnceBodyPart(cont);
        }
    }

    /**
     * Constructor for a signed message with encapsulated content. The encapsulated
     * content, if it exists, is written to the file represented by the File object
     * passed in.
     *
     * @param digCalcProvider provider for digest calculators.
     * @param message the Part containing the signed content.
     * @param file the file the encapsulated part is to be written to after it has been decoded.
     *
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception SMIMEException if the body part encapsulated in the message cannot be extracted.
     * @exception CMSException if some other problem occurs.
     */
    public SMIMESignedParser(
        DigestCalculatorProvider digCalcProvider,
        Part message,
        File file)
        throws MessagingException, CMSException, SMIMEException
    {
        super(digCalcProvider, getInputStream(message));

        this.message = message;

        CMSTypedStream  cont = this.getSignedContent();

        if (cont != null)
        {
            this.content = SMIMEUtil.toMimeBodyPart(cont, file);
        }
    }

    /**
     * return the content that was signed.
     * @return the signed body part in this message.
     */
    public MimeBodyPart getContent()
    {
        return content;
    }

    /**
     * Return the content that was signed as a mime message.
     *
     * @param session the session to base the MimeMessage around.
     * @return a MimeMessage holding the content.
     * @throws MessagingException if there is an issue creating the MimeMessage.
     * @throws IOException if there is an issue reading the content.
     */
    public MimeMessage getContentAsMimeMessage(Session session)
        throws MessagingException, IOException
    {
        if (message instanceof MimeMultipart)
        {
            BodyPart    bp = ((MimeMultipart)message).getBodyPart(0);
            return new MimeMessage(session, bp.getInputStream());
        }
        else
        {
            return new MimeMessage(session, getSignedContent().getContentStream());
        }
    }

    /**
     * return the content that was signed with its signature attached.
     * @return depending on whether this was unencapsulated or not it will return a MimeMultipart
     * or a MimeBodyPart
     */
    public Object getContentWithSignature()
    {
        return message;
    }
    
    private void drainContent() 
        throws CMSException
    {
        try
        {
            this.getSignedContent().drain();
        }
        catch (IOException e)
        {
            throw new CMSException("unable to read content for verification: " + e, e);
        }
    }
    
    private static class TemporaryFileInputStream
        extends BufferedInputStream
    {
        private final File _file;
        
        TemporaryFileInputStream(File file) 
            throws FileNotFoundException
        {
            super(new FileInputStream(file));
            
            _file = file;
        }
        
        public void close() 
            throws IOException
        {
            super.close();

            _file.delete();
        }
    }
}
