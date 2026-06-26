package org.bouncycastle.cms.jcajce;

import java.security.Key;
import java.security.Provider;
import java.util.Set;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.AbstractRecipient;
import org.bouncycastle.cms.CMSAlgorithmNotAllowedException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KEKRecipient;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyUnwrapper;

public abstract class JceKEKRecipient
    extends AbstractRecipient
    implements KEKRecipient
{
    private SecretKey recipientKey;

    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    protected EnvelopedDataHelper contentHelper = helper;
    protected boolean validateKeySize = false;

    public JceKEKRecipient(SecretKey recipientKey)
    {
        this.recipientKey = recipientKey;
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param provider provider to use.
     * @return this recipient.
     */
    public JceKEKRecipient setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public JceKEKRecipient setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Set the provider to use for content processing.
     *
     * @param provider the provider to use.
     * @return this recipient.
     */
    public JceKEKRecipient setContentProvider(Provider provider)
    {
        this.contentHelper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

        return this;
    }

    /**
     * Set the provider to use for content processing.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public JceKEKRecipient setContentProvider(String providerName)
    {
        this.contentHelper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

        return this;
    }

    /**
     * Set validation of retrieved key sizes against the algorithm parameters for the encrypted key where possible - default is off.
     * <p>
     * This setting will not have any affect if the encryption algorithm in the recipient does not specify a particular key size, or
     * if the unwrapper is a HSM and the byte encoding of the unwrapped secret key is not available.
     * </p>
     * @param doValidate true if unwrapped key's should be validated against the content encryption algorithm, false otherwise.
     * @return this recipient.
     */
    public JceKEKRecipient setKeySizeValidation(boolean doValidate)
    {
        this.validateKeySize = doValidate;

        return this;
    }

    /**
     * Set the content-encryption algorithms this recipient is willing to unwrap a key for. When set, an
     * attempt to recover content protected under any other algorithm is rejected, mitigating an attacker
     * substituting a weaker content-encryption algorithm into the recipient info.
     *
     * @param allowedContentAlgorithms the set of permitted content-encryption algorithm OIDs.
     * @return this recipient.
     */
    public JceKEKRecipient setAllowedContentAlgorithms(Set<ASN1ObjectIdentifier> allowedContentAlgorithms)
    {
        setAllowedContentAlgorithmSet(allowedContentAlgorithms);

        return this;
    }

    /**
     * Set the minimum AEAD authentication tag size (in bits) this recipient will accept. When set, an
     * attempt to recover AuthEnvelopedData whose content algorithm carries a shorter tag is rejected,
     * mitigating an attacker downgrading the tag to a weaker length.
     *
     * @param tagSizeInBits the minimum acceptable AEAD tag size, in bits.
     * @return this recipient.
     */
    public JceKEKRecipient setMinimumTagSize(int tagSizeInBits)
    {
        setMinimumTagSizeInBits(tagSizeInBits);

        return this;
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        if (!isContentAlgorithmAllowed(encryptedKeyAlgorithm.getAlgorithm()))
        {
            throw new CMSAlgorithmNotAllowedException("content-encryption algorithm not in recipient's allowed set: " + encryptedKeyAlgorithm.getAlgorithm());
        }

        checkTagSize(encryptedKeyAlgorithm);

        SymmetricKeyUnwrapper unwrapper = helper.createSymmetricUnwrapper(keyEncryptionAlgorithm, recipientKey);

        try
        {
            Key key =  helper.getJceKey(encryptedKeyAlgorithm, unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedContentEncryptionKey));

            if (validateKeySize)
            {
                helper.keySizeCheck(encryptedKeyAlgorithm, key);
            }

            return key;
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
