package org.bouncycastle.cms.bc;

import java.math.BigInteger;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.AbstractRecipient;
import org.bouncycastle.cms.CMSAlgorithmNotAllowedException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Properties;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a password.
 */
public abstract class BcPasswordRecipient
    extends AbstractRecipient
    implements PasswordRecipient
{
    private final char[] password;

    private int schemeID = PasswordRecipient.PKCS5_SCHEME2_UTF8;

    BcPasswordRecipient(
        char[] password)
    {
        this.password = password;
    }

    public BcPasswordRecipient setPasswordConversionScheme(int schemeID)
    {
        this.schemeID = schemeID;

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
    public BcPasswordRecipient setAllowedContentAlgorithms(Set<ASN1ObjectIdentifier> allowedContentAlgorithms)
    {
        setAllowedContentAlgorithmSet(allowedContentAlgorithms);

        return this;
    }

    protected KeyParameter extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        if (!isContentAlgorithmAllowed(contentEncryptionAlgorithm.getAlgorithm()))
        {
            throw new CMSAlgorithmNotAllowedException("content-encryption algorithm not in recipient's allowed set: " + contentEncryptionAlgorithm.getAlgorithm());
        }

        checkTagSize(contentEncryptionAlgorithm);

        Wrapper keyEncryptionCipher = EnvelopedDataHelper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

        keyEncryptionCipher.init(false, new ParametersWithIV(new KeyParameter(derivedKey), ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets()));

        try
        {
            return new KeyParameter(keyEncryptionCipher.unwrap(encryptedContentEncryptionKey, 0, encryptedContentEncryptionKey.length));
        }
        catch (InvalidCipherTextException e)
        {
            throw new CMSException("unable to unwrap key: " + e.getMessage(), e);
        }
    }

    public byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
        throws CMSException
    {
        PBKDF2Params params = PBKDF2Params.getInstance(derivationAlgorithm.getParameters());
        byte[] encodedPassword = (schemeID == PasswordRecipient.PKCS5_SCHEME2) ? PBEParametersGenerator.PKCS5PasswordToBytes(password) : PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);

        // The PBKDF2 iteration count comes from the keyDerivationAlgorithm of the PasswordRecipientInfo
        // (RFC 5652 sec. 6.2.4; RFC 3211 sec. 2.1 mandates PBKDF2) and is both attacker-supplied and
        // unauthenticated - EnvelopedData carries no integrity protection, so the KDF runs before anything
        // is verified, and RFC 8018 App. A.2 permits iterationCount up to MAX on the wire. Bound it (default
        // 10,000,000, the count RFC 8018 sec. 4.2 deems appropriate for especially critical keys) to cap CPU cost.
        BigInteger iterationCount = params.getIterationCount();
        long max = Properties.asInteger(Properties.PBE_MAX_ITERATION_COUNT, 10000000);
        if (iterationCount.bitLength() > 31 || iterationCount.longValue() > max)
        {
            throw new CMSException("iteration count (" + iterationCount + ") greater than " + max);
        }

        try
        {
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(EnvelopedDataHelper.getPRF(params.getPrf()));

            gen.init(encodedPassword, params.getSalt(), iterationCount.intValue());

            return ((KeyParameter)gen.generateDerivedParameters(keySize)).getKey();
        }
        catch (Exception e)
        {
            throw new CMSException("exception creating derived key: " + e.getMessage(), e);
        }
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
