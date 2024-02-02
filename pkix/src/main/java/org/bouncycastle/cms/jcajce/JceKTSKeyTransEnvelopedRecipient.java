package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientOperator;

/**
 * the KeyTransRecipient class for a recipient who has been sent secret
 * key material encrypted using their public key that needs to be used to
 * derive a key and extract a message.
 */
public class JceKTSKeyTransEnvelopedRecipient
    extends JceKTSKeyTransRecipient
{
    public JceKTSKeyTransEnvelopedRecipient(PrivateKey recipientKey, KeyTransRecipientId recipientId)
        throws IOException
    {
        super(recipientKey, getPartyVInfoFromRID(recipientId));
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);
        return CMSUtils.getRecipientOperator(contentEncryptionAlgorithm, secretKey, contentHelper);
    }
}
