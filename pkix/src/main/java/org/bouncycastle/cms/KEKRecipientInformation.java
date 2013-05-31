package org.bouncycastle.cms;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipient;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a secret key known to the other side.
 */
public class KEKRecipientInformation
    extends RecipientInformation
{
    private KEKRecipientInfo      info;

    KEKRecipientInformation(
        KEKRecipientInfo        info,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable,
        AuthAttributesProvider  additionalData)
    {
        super(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData);

        this.info = info;

        KEKIdentifier kekId = info.getKekid();

        this.rid = new KEKRecipientId(kekId.getKeyIdentifier().getOctets());
    }

    /**
     * decrypt the content and return an input stream.
     */
    public CMSTypedStream getContentStream(
        Key      key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(prov));
    }

    /**
     * decrypt the content and return an input stream.
     * @deprecated use getContentStream(Recipient)
     */
    public CMSTypedStream getContentStream(
        Key      key,
        Provider prov)
        throws CMSException
    {
        try
        {
            JceKEKRecipient recipient;

            if (secureReadable instanceof CMSEnvelopedHelper.CMSEnvelopedSecureReadable)
            {
                recipient = new JceKEKEnvelopedRecipient((SecretKey)key);
            }
            else
            {
                recipient = new JceKEKAuthenticatedRecipient((SecretKey)key);
            }

            if (prov != null)
            {
                recipient.setProvider(prov);
            }

            return getContentStream(recipient);
        }
        catch (IOException e)
        {
            throw new CMSException("encoding error: " + e.getMessage(), e);
        }
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException, IOException
    {
        return ((KEKRecipient)recipient).getRecipientOperator(keyEncAlg, messageAlgorithm, info.getEncryptedKey().getOctets());
    }
}
