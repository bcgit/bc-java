package org.bouncycastle.cms;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class KeyTransRecipientInformation
    extends RecipientInformation
{
    private KeyTransRecipientInfo info;

    KeyTransRecipientInformation(
        KeyTransRecipientInfo   info,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable,
        AuthAttributesProvider  additionalData)
    {
        super(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData);

        this.info = info;

        RecipientIdentifier r = info.getRecipientIdentifier();

        if (r.isTagged())
        {
            ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

            rid = new KeyTransRecipientId(octs.getOctets());
        }
        else
        {
            IssuerAndSerialNumber   iAnds = IssuerAndSerialNumber.getInstance(r.getId());

            rid = new KeyTransRecipientId(iAnds.getName(), iAnds.getSerialNumber().getValue());
        }
    }

    /**
     * decrypt the content and return it
     * @deprecated use getContentStream(Recipient) method
     */
    public CMSTypedStream getContentStream(
        Key key,
        String prov)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(prov));
    }

    /**
     * decrypt the content and return it
     * @deprecated use getContentStream(Recipient) method
     */
    public CMSTypedStream getContentStream(
        Key key,
        Provider prov)
        throws CMSException
    {
        try
        {
            JceKeyTransRecipient recipient;

            if (secureReadable instanceof CMSEnvelopedHelper.CMSEnvelopedSecureReadable)
            {
                recipient = new JceKeyTransEnvelopedRecipient((PrivateKey)key);
            }
            else
            {
                recipient = new JceKeyTransAuthenticatedRecipient((PrivateKey)key);
            }

            if (prov != null)
            {
                recipient.setProvider(prov);
                if (prov.getName().equalsIgnoreCase("SunJCE"))
                {
                    recipient.setContentProvider((String)null);    // need to fall back to generic search
                }
            }

            return getContentStream(recipient);
        }
        catch (IOException e)
        {
            throw new CMSException("encoding error: " + e.getMessage(), e);
        }
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException
    {
        return ((KeyTransRecipient)recipient).getRecipientOperator(keyEncAlg, messageAlgorithm, info.getEncryptedKey().getOctets());
    }
}
