package org.bouncycastle.cms.jcajce;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Provider;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.AbstractRecipient;
import org.bouncycastle.cms.CMSAlgorithmNotAllowedException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.PasswordRecipient;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a password.
 */
public abstract class JcePasswordRecipient
    extends AbstractRecipient
    implements PasswordRecipient
{
    private int schemeID = PasswordRecipient.PKCS5_SCHEME2_UTF8;
    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private char[] password;

    JcePasswordRecipient(
        char[] password)
    {
        this.password = password;
    }

    public JcePasswordRecipient setPasswordConversionScheme(int schemeID)
    {
        this.schemeID = schemeID;

        return this;
    }

    public JcePasswordRecipient setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

        return this;
    }

    public JcePasswordRecipient setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

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
    public JcePasswordRecipient setAllowedContentAlgorithms(Set<ASN1ObjectIdentifier> allowedContentAlgorithms)
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
    public JcePasswordRecipient setMinimumTagSize(int tagSizeInBits)
    {
        setMinimumTagSizeInBits(tagSizeInBits);

        return this;
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        if (!isContentAlgorithmAllowed(contentEncryptionAlgorithm.getAlgorithm()))
        {
            throw new CMSAlgorithmNotAllowedException("content-encryption algorithm not in recipient's allowed set: " + contentEncryptionAlgorithm.getAlgorithm());
        }

        checkTagSize(contentEncryptionAlgorithm);

        Cipher keyEncryptionCipher = helper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

        try
        {
            IvParameterSpec ivSpec = new IvParameterSpec(ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets());

            keyEncryptionCipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(derivedKey, keyEncryptionCipher.getAlgorithm()), ivSpec);

            return keyEncryptionCipher.unwrap(encryptedContentEncryptionKey, contentEncryptionAlgorithm.getAlgorithm().getId(), Cipher.SECRET_KEY);
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot process content encryption key: " + e.getMessage(), e);
        }
    }

    public byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
        throws CMSException
    {
        return helper.calculateDerivedKey(schemeID, password, derivationAlgorithm, keySize);
    }

    public int getPasswordConversionScheme()
    {
        return schemeID;
    }

    public char[] getPassword()
    {
        return password;
    }
}
