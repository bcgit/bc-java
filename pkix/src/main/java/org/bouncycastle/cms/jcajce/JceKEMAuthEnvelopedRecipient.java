package org.bouncycastle.cms.jcajce;

import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;

/**
 * The KEM (RFC 9629 KEMRecipientInfo) recipient for CMS AuthEnvelopedData: decapsulates the
 * key-encryption key and returns an AEAD input decryptor (e.g. AES-GCM) that verifies the
 * authentication tag, the AuthEnveloped counterpart of {@link JceKEMEnvelopedRecipient}.
 */
public class JceKEMAuthEnvelopedRecipient
    extends JceKEMRecipient
{
    public JceKEMAuthEnvelopedRecipient(PrivateKey recipientKey)
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
