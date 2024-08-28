package org.bouncycastle.cms.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSInputAEADDecryptor;
import org.bouncycastle.cms.RecipientOperator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;

public class JceKEKAuthEnvelopedRecipient
        extends JceKEKRecipient
{
    public JceKEKAuthEnvelopedRecipient(SecretKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
            throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new CMSInputAEADDecryptor(contentEncryptionAlgorithm, dataCipher));
    }
}
