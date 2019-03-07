package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JceKTSKeyUnwrapper;
import org.bouncycastle.util.encoders.Hex;

public abstract class JceKTSKeyTransRecipient
    implements KeyTransRecipient
{
    private static final byte[] ANONYMOUS_SENDER = Hex.decode("0c14416e6f6e796d6f75732053656e64657220202020");   // "Anonymous Sender    "
    private final byte[] partyVInfo;

    private PrivateKey recipientKey;

    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    protected EnvelopedDataHelper contentHelper = helper;
    protected Map extraMappings = new HashMap();
    protected boolean validateKeySize = false;
    protected boolean unwrappedKeyMustBeEncodable;

    public JceKTSKeyTransRecipient(PrivateKey recipientKey, byte[] partyVInfo)
    {
        this.recipientKey = CMSUtils.cleanPrivateKey(recipientKey);
        this.partyVInfo = partyVInfo;
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param provider provider to use.
     * @return this recipient.
     */
    public JceKTSKeyTransRecipient setProvider(Provider provider)
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
    public JceKTSKeyTransRecipient setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Internally algorithm ids are converted into cipher names using a lookup table. For some providers
     * the standard lookup table won't work. Use this method to establish a specific mapping from an
     * algorithm identifier to a specific algorithm.
     * <p>
     *     For example:
     * <pre>
     *     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
     * </pre>
     * @param algorithm  OID of algorithm in recipient.
     * @param algorithmName JCE algorithm name to use.
     * @return the current Recipient.
     */
    public JceKTSKeyTransRecipient setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        extraMappings.put(algorithm, algorithmName);

        return this;
    }

    /**
     * Set the provider to use for content processing.  If providerName is null a "no provider" search will be
     * used to satisfy getInstance calls.
     *
     * @param provider the provider to use.
     * @return this recipient.
     */
    public JceKTSKeyTransRecipient setContentProvider(Provider provider)
    {
        this.contentHelper = CMSUtils.createContentHelper(provider);

        return this;
    }

    /**
     * Set the provider to use for content processing.  If providerName is null a "no provider" search will be
     *  used to satisfy getInstance calls.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public JceKTSKeyTransRecipient setContentProvider(String providerName)
    {
        this.contentHelper = CMSUtils.createContentHelper(providerName);

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
    public JceKTSKeyTransRecipient setKeySizeValidation(boolean doValidate)
    {
        this.validateKeySize = doValidate;

        return this;
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
        throws CMSException
    {
        JceKTSKeyUnwrapper unwrapper = helper.createAsymmetricUnwrapper(keyEncryptionAlgorithm, recipientKey, ANONYMOUS_SENDER, partyVInfo);

        try
        {
            Key key = helper.getJceKey(encryptedKeyAlgorithm.getAlgorithm(), unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));

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

    protected static byte[] getPartyVInfoFromRID(KeyTransRecipientId recipientId)
        throws IOException
    {
        if (recipientId.getSerialNumber() != null)
        {
            return new IssuerAndSerialNumber(recipientId.getIssuer(), recipientId.getSerialNumber()).getEncoded(ASN1Encoding.DER);
        }
        else
        {
            return new DEROctetString(recipientId.getSubjectKeyIdentifier()).getEncoded();
        }
    }
}
