package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.CollectionStore;

/**
 * A tool kit of common tasks.
 */
public class SMIMEToolkit
{
    private final DigestCalculatorProvider digestCalculatorProvider;

    /**
     * Base constructor.
     * 
     * @param digestCalculatorProvider  provider for any digest calculations required.
     */
    public SMIMEToolkit(DigestCalculatorProvider digestCalculatorProvider)
    {
        this.digestCalculatorProvider = digestCalculatorProvider;
    }
    
    /**
     * Return true if the passed in message (MimeBodyPart or MimeMessage) is encrypted.
     *
     * @param message message of interest
     * @return true if the message represents an encrypted message, false otherwise.
     * @throws MessagingException on a message processing issue.
     */
    public boolean isEncrypted(Part message)
        throws MessagingException
    {
        return message.getHeader("Content-Type")[0].equals("application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data");
    }

    /**
     * Return true if the passed in message (MimeBodyPart or MimeMessage) is a signed one.
     *
     * @param message message of interest
     * @return true if the message represents a signed message, false otherwise.
     * @throws MessagingException on a message processing issue.
     */
    public boolean isSigned(Part message)
        throws MessagingException
    {
        return message.getHeader("Content-Type")[0].startsWith("multipart/signed")
            || message.getHeader("Content-Type")[0].equals("application/pkcs7-mime; name=smime.p7m; smime-type=signed-data");
    }

    /**
     * Return true if the passed in MimeMultipart is a signed one.
     *
     * @param message message of interest
     * @return  true if the multipart has an attached signature, false otherwise.
     * @throws MessagingException on a message processing issue.
     */
    public boolean isSigned(MimeMultipart message)
        throws MessagingException
    {
        return message.getBodyPart(1).getHeader("Content-Type")[0].equals("application/pkcs7-signature; name=smime.p7s; smime-type=signed-data");
    }

    /**
     * Return true if there is a signature on the message that can be verified by the verifier.
     *
     * @param message a MIME part representing a signed message.
     * @param verifier the verifier we want to find a signer for.
     * @return true if cert verifies message, false otherwise.
     * @throws SMIMEException on a SMIME handling issue.
     * @throws MessagingException on a basic message processing exception
     */
    public boolean isValidSignature(Part message, SignerInformationVerifier verifier)
        throws SMIMEException, MessagingException
    {
        try
        {
            SMIMESignedParser s;

            if (message.isMimeType("multipart/signed"))
            {
                s = new SMIMESignedParser(digestCalculatorProvider, (MimeMultipart)message.getContent());
            }
            else
            {
                s = new SMIMESignedParser(digestCalculatorProvider, message);
            }

            return isAtLeastOneValidSigner(s, verifier);
        }
        catch (CMSException e)
        {
            throw new SMIMEException("CMS processing failure: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new SMIMEException("Parsing failure: " + e.getMessage(), e);
        }
    }

    private boolean isAtLeastOneValidSigner(SMIMESignedParser s, SignerInformationVerifier verifier)
        throws CMSException
    {
        if (verifier.hasAssociatedCertificate())
        {
            X509CertificateHolder cert = verifier.getAssociatedCertificate();
            SignerInformation signer = s.getSignerInfos().get(new SignerId(cert.getIssuer(), cert.getSerialNumber()));

            if (signer != null)
            {
                return signer.verify(verifier);
            }
        }

        Collection c = s.getSignerInfos().getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();

            if (signer.verify(verifier))
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Return true if there is a signature on the message that can be verified by verifier..
     *
     * @param message a MIME part representing a signed message.
     * @param verifier the verifier we want to find a signer for.
     * @return true if cert verifies message, false otherwise.
     * @throws SMIMEException on a SMIME handling issue.
     * @throws MessagingException on a basic message processing exception
     */
    public boolean isValidSignature(MimeMultipart message, SignerInformationVerifier verifier)
        throws SMIMEException, MessagingException
    {
        try
        {
            SMIMESignedParser s = new SMIMESignedParser(digestCalculatorProvider, message);

            return isAtLeastOneValidSigner(s, verifier);
        }
        catch (CMSException e)
        {
            throw new SMIMEException("CMS processing failure: " + e.getMessage(), e);
        }
    }


    /**
     * Extract the signer's signing certificate from the message.
     *
     * @param message a MIME part/MIME message representing a signed message.
     * @param signerInformation the signer information identifying the signer of interest.
     * @return the signing certificate, null if not found.
     */
    public X509CertificateHolder extractCertificate(Part message, SignerInformation signerInformation)
        throws SMIMEException, MessagingException
    {
        try
        {
            SMIMESignedParser s;

            if (message instanceof MimeMessage && message.isMimeType("multipart/signed"))
            {
                s = new SMIMESignedParser(digestCalculatorProvider, (MimeMultipart)message.getContent());
            }
            else
            {
                s = new SMIMESignedParser(digestCalculatorProvider, message);
            }

            Collection certCollection = s.getCertificates().getMatches(signerInformation.getSID());

            Iterator certIt = certCollection.iterator();
            if (certIt.hasNext())
            {
                return (X509CertificateHolder)certIt.next();
            }
            return null;
        }
        catch (CMSException e)
        {
            throw new SMIMEException("CMS processing failure: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new SMIMEException("Parsing failure: " + e.getMessage(), e);
        }
    }

    /**
     * Extract the signer's signing certificate from Multipart message content.
     *
     * @param message a MIME Multipart part representing a signed message.
     * @param signerInformation the signer information identifying the signer of interest.
     * @return the signing certificate, null if not found.
     */
    public X509CertificateHolder extractCertificate(MimeMultipart message, SignerInformation signerInformation)
        throws SMIMEException, MessagingException
    {
        try
        {
            SMIMESignedParser s = new SMIMESignedParser(digestCalculatorProvider, message);

            Collection certCollection = s.getCertificates().getMatches(signerInformation.getSID());

            Iterator certIt = certCollection.iterator();
            if (certIt.hasNext())
            {
                return (X509CertificateHolder)certIt.next();
            }
            return null;
        }
        catch (CMSException e)
        {
            throw new SMIMEException("CMS processing failure: " + e.getMessage(), e);
        }
    }

    /**
     * Produce a signed message in multi-part format with the second part containing a detached signature for the first.
     *
     * @param message the message to be signed.
     * @param signerInfoGenerator the generator to be used to generate the signature.
     * @return the resulting MimeMultipart
     * @throws SMIMEException on an exception calculating or creating the signed data.
     */
    public MimeMultipart sign(MimeBodyPart message, SignerInfoGenerator signerInfoGenerator)
        throws SMIMEException
    {
        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        if (signerInfoGenerator.hasAssociatedCertificate())
        {
            List certList = new ArrayList();

            certList.add(signerInfoGenerator.getAssociatedCertificate());

            gen.addCertificates(new CollectionStore(certList));
        }

        gen.addSignerInfoGenerator(signerInfoGenerator);

        return gen.generate(message);
    }

    /**
     * Produce a signed message in encapsulated format where the message is encoded in the signature..
     *
     * @param message the message to be signed.
     * @param signerInfoGenerator the generator to be used to generate the signature.
     * @return a BodyPart containing the encapsulated message.
     * @throws SMIMEException on an exception calculating or creating the signed data.
     */
    public MimeBodyPart signEncapsulated(MimeBodyPart message, SignerInfoGenerator signerInfoGenerator)
        throws SMIMEException
    {
        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        if (signerInfoGenerator.hasAssociatedCertificate())
        {
            List certList = new ArrayList();

            certList.add(signerInfoGenerator.getAssociatedCertificate());

            gen.addCertificates(new CollectionStore(certList));
        }

        gen.addSignerInfoGenerator(signerInfoGenerator);

        return gen.generateEncapsulated(message);
    }

    /**
     * Encrypt the passed in MIME part returning a new encrypted MIME part.
     *
     * @param mimePart the part to be encrypted.
     * @param contentEncryptor the encryptor to use for the actual message content.
     * @param recipientGenerator  the generator for the target recipient.
     * @return an encrypted MIME part.
     * @throws SMIMEException in the event of an exception creating the encrypted part.
     */
    public MimeBodyPart encrypt(MimeBodyPart mimePart, OutputEncryptor contentEncryptor, RecipientInfoGenerator recipientGenerator)
        throws SMIMEException
    {
        SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

        envGen.addRecipientInfoGenerator(recipientGenerator);

        return envGen.generate(mimePart, contentEncryptor);
    }

    /**
     * Encrypt the passed in MIME multi-part returning a new encrypted MIME part.
     *
     * @param multiPart the multi-part to be encrypted.
     * @param contentEncryptor the encryptor to use for the actual message content.
     * @param recipientGenerator  the generator for the target recipient.
     * @return an encrypted MIME part.
     * @throws SMIMEException in the event of an exception creating the encrypted part.
     */
    public MimeBodyPart encrypt(MimeMultipart multiPart, OutputEncryptor contentEncryptor, RecipientInfoGenerator recipientGenerator)
        throws SMIMEException, MessagingException
    {
        SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

        envGen.addRecipientInfoGenerator(recipientGenerator);

        MimeBodyPart bodyPart = new MimeBodyPart();

        bodyPart.setContent(multiPart);

        return envGen.generate(bodyPart, contentEncryptor);
    }

    /**
     * Encrypt the passed in MIME message returning a new encrypted MIME part.
     *
     * @param message the multi-part to be encrypted.
     * @param contentEncryptor the encryptor to use for the actual message content.
     * @param recipientGenerator  the generator for the target recipient.
     * @return an encrypted MIME part.
     * @throws SMIMEException in the event of an exception creating the encrypted part.
     */
    public MimeBodyPart encrypt(MimeMessage message, OutputEncryptor contentEncryptor, RecipientInfoGenerator recipientGenerator)
        throws SMIMEException
    {
        SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

        envGen.addRecipientInfoGenerator(recipientGenerator);

        return envGen.generate(message, contentEncryptor);
    }

    /**
     * Decrypt the passed in MIME part returning a part representing the decrypted content.
     *
     * @param mimePart the part containing the encrypted data.
     * @param recipientId the recipient id in the date to be matched.
     * @param recipient the recipient to be used if a match is found.
     * @return a MIME part containing the decrypted content or null if the recipientId cannot be matched.
     * @throws SMIMEException on an exception doing the decryption.
     * @throws MessagingException on an exception parsing the message,
     */
    public MimeBodyPart decrypt(MimeBodyPart mimePart, RecipientId recipientId, Recipient recipient)
        throws SMIMEException, MessagingException
    {
        try
        {
            SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(mimePart);

            RecipientInformationStore recipients = m.getRecipientInfos();
            RecipientInformation recipientInformation = recipients.get(recipientId);

            if (recipientInformation == null)
            {
                return null;
            }

            return SMIMEUtil.toMimeBodyPart(recipientInformation.getContent(recipient));
        }
        catch (CMSException e)
        {
            throw new SMIMEException("CMS processing failure: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new SMIMEException("Parsing failure: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt the passed in MIME message returning a part representing the decrypted content.
     *
     * @param message the message containing the encrypted data.
     * @param recipientId the recipient id in the date to be matched.
     * @param recipient the recipient to be used if a match is found.
     * @return a MIME part containing the decrypted content, or null if the recipientId cannot be matched.
     * @throws SMIMEException on an exception doing the decryption.
     * @throws MessagingException on an exception parsing the message,
     */
    public MimeBodyPart decrypt(MimeMessage message, RecipientId recipientId, Recipient recipient)
        throws SMIMEException, MessagingException
    {
        try
        {
            SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(message);

            RecipientInformationStore recipients = m.getRecipientInfos();
            RecipientInformation recipientInformation = recipients.get(recipientId);

            if (recipientInformation == null)
            {
                return null;
            }

            return SMIMEUtil.toMimeBodyPart(recipientInformation.getContent(recipient));
        }
        catch (CMSException e)
        {
            throw new SMIMEException("CMS processing failure: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new SMIMEException("Parsing failure: " + e.getMessage(), e);
        }
    }
}
