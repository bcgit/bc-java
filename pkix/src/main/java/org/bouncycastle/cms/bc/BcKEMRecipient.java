package org.bouncycastle.cms.bc;

import java.io.IOException;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSORIforKEMOtherInfo;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.AbstractRecipient;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KEMRecipient;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Base class for recovering the content-encryption key from an RFC 9629 KEMRecipientInfo using the
 * light-weight API. The recipient's key must be an ML-KEM private key.
 */
public abstract class BcKEMRecipient
    extends AbstractRecipient
    implements KEMRecipient
{
    private final MLKEMPrivateKeyParameters recipientKey;

    public BcKEMRecipient(AsymmetricKeyParameter recipientKey)
    {
        if (!(recipientKey instanceof MLKEMPrivateKeyParameters))
        {
            throw new IllegalArgumentException("KEM recipient key must be an ML-KEM private key");
        }

        this.recipientKey = (MLKEMPrivateKeyParameters)recipientKey;
    }

    /**
     * Set the content-encryption algorithms this recipient is willing to unwrap a key for. When set, an
     * attempt to recover content protected under any other algorithm is rejected, mitigating an attacker
     * substituting a weaker content-encryption algorithm into the recipient info.
     *
     * @param allowedContentAlgorithms the set of permitted content-encryption algorithm OIDs.
     * @return this recipient.
     */
    public BcKEMRecipient setAllowedContentAlgorithms(Set<ASN1ObjectIdentifier> allowedContentAlgorithms)
    {
        setAllowedContentAlgorithmSet(allowedContentAlgorithms);

        return this;
    }

    protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        checkContentAlgorithm(contentEncryptionAlgorithm);

        KEMRecipientInfo kemInfo = KEMRecipientInfo.getInstance(keyEncryptionAlgorithm.getParameters());
        AlgorithmIdentifier wrapAlgorithm = kemInfo.getWrap();

        int kekLength;
        Wrapper wrapper;
        try
        {
            kekLength = BcKEMUtil.getKekSize(wrapAlgorithm.getAlgorithm());
            wrapper = BcKEMUtil.createWrapper(wrapAlgorithm.getAlgorithm());
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("unable to create KEM unwrapper: " + e.getMessage(), e);
        }

        // RFC 9629 3: "Implementations MUST confirm that the value provided is consistent with the
        // key-encryption algorithm identified in the wrap field below."
        if (kemInfo.getKekLength() != kekLength)
        {
            throw new CMSException("kekLength " + kemInfo.getKekLength() + " inconsistent with wrap algorithm "
                + wrapAlgorithm.getAlgorithm() + ": expected " + kekLength);
        }

        MLKEMExtractor extractor = new MLKEMExtractor(recipientKey);
        byte[] kemct = kemInfo.getKemct().getOctets();

        if (kemct.length != extractor.getEncapsulationLength())
        {
            throw new CMSException("KEM ciphertext length " + kemct.length + " does not match recipient key: expected "
                + extractor.getEncapsulationLength());
        }

        byte[] kek = null;
        try
        {
            byte[] oriInfoEnc = new CMSORIforKEMOtherInfo(wrapAlgorithm, kekLength, kemInfo.getUkm()).getEncoded();

            kek = BcKEMUtil.deriveKek(kemInfo.getKdf(), extractor.extractSecret(kemct), oriInfoEnc, kekLength);

            wrapper.init(false, new KeyParameter(kek));

            return new KeyParameter(wrapper.unwrap(encryptedContentEncryptionKey, 0, encryptedContentEncryptionKey.length));
        }
        catch (InvalidCipherTextException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
        finally
        {
            if (kek != null)
            {
                Arrays.clear(kek);
            }
        }
    }
}
