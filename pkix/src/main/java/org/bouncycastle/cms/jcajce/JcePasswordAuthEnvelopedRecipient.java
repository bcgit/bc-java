package org.bouncycastle.cms.jcajce;

import java.security.Key;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;

public class JcePasswordAuthEnvelopedRecipient
    extends JcePasswordRecipient
{
    public JcePasswordAuthEnvelopedRecipient(char[] password)
    {
        super(password);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
                                                  final AlgorithmIdentifier contentMacAlgorithm,
                                                  byte[] derivedKey,
                                                  byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, derivedKey, encryptedContentEncryptionKey);

        final Cipher dataCipher = helper.createContentCipher(secretKey, contentMacAlgorithm);

        return new RecipientOperator(new CMSInputAEADDecryptor(contentMacAlgorithm, dataCipher));
    }
}
