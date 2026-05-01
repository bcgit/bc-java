package org.bouncycastle.cms.jcajce;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;

import javax.crypto.Cipher;

import java.security.Key;
import java.security.PrivateKey;

/**
 * A recipient class for CMS authenticated enveloped data using key agreement (Key Agreement Recipient).
 * Handles private key-based key extraction and content decryption.
 */
public class JceKeyAgreeAuthEnvelopedRecipient
    extends JceKeyAgreeRecipient
{
    public JceKeyAgreeAuthEnvelopedRecipient(PrivateKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, SubjectPublicKeyInfo senderPublicKey, ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, senderPublicKey, userKeyingMaterial, encryptedContentKey);

        final Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new CMSInputAEADDecryptor(contentEncryptionAlgorithm, dataCipher));
    }
}
