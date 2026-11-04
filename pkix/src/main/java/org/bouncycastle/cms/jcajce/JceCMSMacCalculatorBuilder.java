package org.bouncycastle.cms.jcajce;

import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jcajce.io.MacOutputStream;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.jcajce.JceGenericKey;

/**
 * Builder for the MAC calculator of a CMS AuthenticatedData message.
 * <p>
 * Prefer an HMAC, such as {@code PKCSObjectIdentifiers.id_hmacWithSHA256}, or KMAC. The CBC-MACs
 * named by {@link org.bouncycastle.cms.CMSAlgorithm#DES_EDE3_CBC} and
 * {@link org.bouncycastle.cms.CMSAlgorithm#RC2_CBC} are kept for compatibility: they produce a
 * 4-byte MAC, and when the message has no authenticated attributes the MAC covers the content alone,
 * so any IV in the macAlgorithm parameters is unprotected. Unless parameters are set with
 * {@link #setAlgorithmParameters(AlgorithmParameters)} these are therefore written with a zero IV,
 * and a non-zero IV is refused for a message without authenticated attributes, on generation and on
 * receipt (see {@code org.bouncycastle.util.Properties.CMS_ALLOW_UNAUTHENTICATED_CBC_MAC_IV}).
 */
public class JceCMSMacCalculatorBuilder
{
    private final ASN1ObjectIdentifier macOID;
    private final int                  keySize;

    private EnvelopedDataHelper helper = CMSUtils.createDefaultHelper();
    private AlgorithmParameters algorithmParameters;
    private SecureRandom random;

    public JceCMSMacCalculatorBuilder(ASN1ObjectIdentifier macOID)
    {
        this(macOID, -1);
    }

    public JceCMSMacCalculatorBuilder(ASN1ObjectIdentifier macOID, int keySize)
    {
        this.macOID = macOID;
        this.keySize = keySize;
    }

    /**
     * Set the provider to use for content encryption.
     *
     * @param provider the provider object to use for MAC and default parameters creation.
     * @return the current builder instance.
     */
    public JceCMSMacCalculatorBuilder setProvider(Provider provider)
    {
        this.helper = CMSUtils.createProviderHelper(provider);

        return this;
    }

    /**
     * Set the provider to use for content encryption (by name)
     *
     * @param providerName the name of the provider to use for MAC and default parameters creation.
     * @return the current builder instance.
     */
    public JceCMSMacCalculatorBuilder setProvider(String providerName)
    {
        this.helper = CMSUtils.createNamedHelper(providerName);

        return this;
    }

    /**
     * Provide a specified source of randomness to be used for session key and IV/nonce generation.
     *
     * @param random the secure random to use.
     * @return the current builder instance.
     */
    public JceCMSMacCalculatorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Provide a set of algorithm parameters for the content MAC calculator to use.
     * <p>
     * For a CBC-MAC (des-ede3-cbc or rc2-cbc) parameters carrying a non-zero IV can only be used for
     * a message with authenticated attributes, which bind the content; without them the generator
     * refuses the IV, as it is not covered by the MAC.
     *
     * @param algorithmParameters algorithmParameters for MAC initialisation.
     * @return the current builder instance.
     */
    public JceCMSMacCalculatorBuilder setAlgorithmParameters(AlgorithmParameters algorithmParameters)
    {
        this.algorithmParameters = algorithmParameters;

        return this;
    }

    public MacCalculator build()
        throws CMSException
    {
        return new CMSMacCalculator(macOID, keySize, algorithmParameters, random);
    }

    private class CMSMacCalculator
        implements MacCalculator
    {
        private SecretKey encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        private Mac mac;

        CMSMacCalculator(ASN1ObjectIdentifier macOID, int keySize, AlgorithmParameters params, SecureRandom random)
            throws CMSException
        {
            KeyGenerator keyGen = helper.createKeyGenerator(macOID);

            if (random == null)
            {
                random = new SecureRandom();
            }

            if (keySize < 0)
            {
                keyGen.init(random);
            }
            else
            {
                keyGen.init(keySize, random);
            }

            encKey = keyGen.generateKey();

            if (params == null)
            {
                if (CMSAlgorithm.DES_EDE3_CBC.equals(macOID) || CMSAlgorithm.RC2_CBC.equals(macOID))
                {
                    // a CBC-MAC IV is not covered by the MAC when authAttrs are absent (RFC 5652 sec. 9.2), so start from zero
                    params = createZeroIVParameters(macOID, encKey);
                }
                else
                {
                    params = helper.generateParameters(macOID, encKey, random);
                }
            }

            if (params == null && isKMACwithSHAKE(macOID))
            {
                // RFC 8702 sec.3.4 - KMACwithSHAKE128/256 parameters are OPTIONAL;
                // omit them to signal the defaults (256/512-bit output, empty
                // customization) rather than emitting a NULL placeholder.
                algorithmIdentifier = new AlgorithmIdentifier(macOID);
            }
            else
            {
                algorithmIdentifier = helper.getAlgorithmIdentifier(macOID, params);
            }
            mac = helper.createContentMac(encKey, algorithmIdentifier);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        private AlgorithmParameters createZeroIVParameters(ASN1ObjectIdentifier macOID, SecretKey encKey)
            throws CMSException
        {
            try
            {
                AlgorithmParameters params = helper.createAlgorithmParameters(macOID);

                if (CMSAlgorithm.RC2_CBC.equals(macOID))
                {
                    params.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, new byte[8]));
                }
                else
                {
                    params.init(new IvParameterSpec(new byte[8]));
                }

                return params;
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("unable to create MAC parameters: " + e.getMessage(), e);
            }
        }

        public OutputStream getOutputStream()
        {
            return new MacOutputStream(mac);
        }

        public byte[] getMac()
        {
            return mac.doFinal();
        }

        public GenericKey getKey()
        {
            return new JceGenericKey(algorithmIdentifier, encKey);
        }
    }

    private static boolean isKMACwithSHAKE(ASN1ObjectIdentifier macOID)
    {
        return NISTObjectIdentifiers.id_KmacWithSHAKE128.equals(macOID)
            || NISTObjectIdentifiers.id_KmacWithSHAKE256.equals(macOID);
    }
}
