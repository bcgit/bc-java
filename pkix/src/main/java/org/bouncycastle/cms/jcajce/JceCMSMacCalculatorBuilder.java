package org.bouncycastle.cms.jcajce;

import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jcajce.io.MacOutputStream;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.jcajce.JceGenericKey;

public class JceCMSMacCalculatorBuilder
{
    private final ASN1ObjectIdentifier macOID;
    private final int                  keySize;

    private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
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
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

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
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

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
                params = helper.generateParameters(macOID, encKey, random);
            }

            algorithmIdentifier = helper.getAlgorithmIdentifier(macOID, params);
            mac = helper.createContentMac(encKey, algorithmIdentifier);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
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
}
