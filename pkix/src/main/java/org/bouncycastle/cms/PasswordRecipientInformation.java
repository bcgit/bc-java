package org.bouncycastle.cms;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceAlgorithmIdentifierConverter;
import org.bouncycastle.cms.jcajce.JcePasswordAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipient;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Integers;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a password.
 */
public class PasswordRecipientInformation
    extends RecipientInformation
{
    static Map KEYSIZES = new HashMap();
    static Map BLOCKSIZES = new HashMap();

    static
    {
        BLOCKSIZES.put(CMSAlgorithm.DES_EDE3_CBC, Integers.valueOf(8));
        BLOCKSIZES.put(CMSAlgorithm.AES128_CBC, Integers.valueOf(16));
        BLOCKSIZES.put(CMSAlgorithm.AES192_CBC, Integers.valueOf(16));
        BLOCKSIZES.put(CMSAlgorithm.AES256_CBC, Integers.valueOf(16));

        KEYSIZES.put(CMSAlgorithm.DES_EDE3_CBC, Integers.valueOf(192));
        KEYSIZES.put(CMSAlgorithm.AES128_CBC, Integers.valueOf(128));
        KEYSIZES.put(CMSAlgorithm.AES192_CBC, Integers.valueOf(192));
        KEYSIZES.put(CMSAlgorithm.AES256_CBC, Integers.valueOf(256));
    }

    private PasswordRecipientInfo info;

    PasswordRecipientInformation(
        PasswordRecipientInfo   info,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable,
        AuthAttributesProvider  additionalData)
    {
        super(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData);

        this.info = info;
        this.rid = new PasswordRecipientId();
    }

    /**
     * return the object identifier for the key derivation algorithm, or null
     * if there is none present.
     *
     * @return OID for key derivation algorithm, if present.
     */
    public String getKeyDerivationAlgOID()
    {
        if (info.getKeyDerivationAlgorithm() != null)
        {
            return info.getKeyDerivationAlgorithm().getAlgorithm().getId();
        }

        return null;
    }

    /**
     * return the ASN.1 encoded key derivation algorithm parameters, or null if
     * there aren't any.
     * @return ASN.1 encoding of key derivation algorithm parameters.
     */
    public byte[] getKeyDerivationAlgParams()
    {
        try
        {
            if (info.getKeyDerivationAlgorithm() != null)
            {
                ASN1Encodable params = info.getKeyDerivationAlgorithm().getParameters();
                if (params != null)
                {
                    return params.toASN1Primitive().getEncoded();
                }
            }

            return null;
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * Return the key derivation algorithm details for the key in this recipient.
     *
     * @return AlgorithmIdentifier representing the key derivation algorithm.
     */
    public AlgorithmIdentifier getKeyDerivationAlgorithm()
    {
        return info.getKeyDerivationAlgorithm();
    }

    /**
     * return an AlgorithmParameters object representing the parameters to the
     * key derivation algorithm to the recipient.
     *
     * @return AlgorithmParameters object, null if there aren't any.
     * @deprecated use getKeyDerivationAlgorithm and JceAlgorithmIdentifierConverter().
     */
    public AlgorithmParameters getKeyDerivationAlgParameters(String provider)
        throws NoSuchProviderException
    {
        return getKeyDerivationAlgParameters(CMSUtils.getProvider(provider));
    }
    
   /**
     * return an AlgorithmParameters object representing the parameters to the
     * key derivation algorithm to the recipient.
     *
     * @return AlgorithmParameters object, null if there aren't any.
    *  @deprecated use getKeyDerivationAlgorithm and JceAlgorithmIdentifierConverter().
     */
    public AlgorithmParameters getKeyDerivationAlgParameters(Provider provider)
    {
        try
        {
            return new JceAlgorithmIdentifierConverter().setProvider(provider).getAlgorithmParameters(info.getKeyDerivationAlgorithm());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * decrypt the content and return an input stream.
     * @deprecated use getContentStream(Recipient)
     */
    public CMSTypedStream getContentStream(
        Key key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(prov));
    }

    /**
     * decrypt the content and return an input stream.
     * @deprecated use getContentStream(Recipient)
     */
    public CMSTypedStream getContentStream(
        Key key,
        Provider prov)
        throws CMSException
    {
        try
        {
            CMSPBEKey pbeKey = (CMSPBEKey)key;
            JcePasswordRecipient recipient;

            if (secureReadable instanceof CMSEnvelopedHelper.CMSEnvelopedSecureReadable)
            {
                recipient = new JcePasswordEnvelopedRecipient(pbeKey.getPassword());
            }
            else
            {
                recipient = new JcePasswordAuthenticatedRecipient(pbeKey.getPassword());
            }

            recipient.setPasswordConversionScheme((pbeKey instanceof PKCS5Scheme2UTF8PBEKey) ? PasswordRecipient.PKCS5_SCHEME2_UTF8 : PasswordRecipient.PKCS5_SCHEME2);

            if (prov != null)
            {
                recipient.setProvider(prov);
            }

            return getContentStream(recipient);
        }
        catch (IOException e)
        {
            throw new CMSException("encoding error: " + e.getMessage(), e);
        }
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException, IOException
    {
        PasswordRecipient pbeRecipient = (PasswordRecipient)recipient;
        AlgorithmIdentifier kekAlg = AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm());
        AlgorithmIdentifier kekAlgParams = AlgorithmIdentifier.getInstance(kekAlg.getParameters());

        byte[] passwordBytes = getPasswordBytes(pbeRecipient.getPasswordConversionScheme(),
            pbeRecipient.getPassword());
        PBKDF2Params params = PBKDF2Params.getInstance(info.getKeyDerivationAlgorithm().getParameters());

        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator();
        gen.init(passwordBytes, params.getSalt(), params.getIterationCount().intValue());

        int keySize = ((Integer)KEYSIZES.get(kekAlgParams.getAlgorithm())).intValue();

        byte[] derivedKey = ((KeyParameter)gen.generateDerivedParameters(keySize)).getKey();

        return pbeRecipient.getRecipientOperator(kekAlgParams, messageAlgorithm, derivedKey, info.getEncryptedKey().getOctets());
    }
    
    protected byte[] getPasswordBytes(int scheme, char[] password)
    {
        if (scheme == PasswordRecipient.PKCS5_SCHEME2)
        {
            return PBEParametersGenerator.PKCS5PasswordToBytes(password);
        }

        return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);
    }
}
