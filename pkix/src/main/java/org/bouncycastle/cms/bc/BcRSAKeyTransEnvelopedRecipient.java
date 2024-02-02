package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class BcRSAKeyTransEnvelopedRecipient
    extends BcKeyTransRecipient
{
    public BcRSAKeyTransEnvelopedRecipient(AsymmetricKeyParameter key)
    {
        super(key);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        CipherParameters secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        return CMSUtils.getRecipientOperator(contentEncryptionAlgorithm, secretKey);
    }
}
