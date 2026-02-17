package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * A composite private key class.
 */
public class CompositePrivateKey
    implements PrivateKey
{
    public static class Builder
    {
        private final AlgorithmIdentifier algorithmIdentifier;
        private final PrivateKey[] keys = new PrivateKey[2];
        private final Provider[] providers = new Provider[2];

        private int count = 0;

        private Builder(AlgorithmIdentifier algorithmIdentifier)
        {
            this.algorithmIdentifier = algorithmIdentifier;
        }

        public Builder addPrivateKey(PrivateKey key)
        {
            return addPrivateKey(key, (Provider)null);
        }

        public Builder addPrivateKey(PrivateKey key, String providerName)
        {
            return addPrivateKey(key, Security.getProvider(providerName));
        }

        public Builder addPrivateKey(PrivateKey key, Provider provider)
        {
            if (count == keys.length)
            {
                throw new IllegalStateException("only " + keys.length + " allowed in composite");
            }

            keys[count] = key;
            providers[count++] = provider;

            return this;
        }

        public CompositePrivateKey build()
        {
            if (providers[0] == null && providers[1] == null)
             {
                 return new CompositePrivateKey(algorithmIdentifier, keys, null);
             }

            return new CompositePrivateKey(algorithmIdentifier, keys, providers);
        }
    }

    public static Builder builder(ASN1ObjectIdentifier compAlgOid)
    {
        return new Builder(new AlgorithmIdentifier(compAlgOid));
    }

    public static Builder builder(String algorithmName)
    {
        return builder(CompositeUtil.getOid(algorithmName));
    }

    private final List<PrivateKey> keys;
    private final List<Provider> providers;

    private AlgorithmIdentifier algorithmIdentifier;

    /**
     * Create a composite private key from an array of PublicKeys.
     * This constructor is currently used only for legacy composites implementation.
     *
     * @param keys The component private keys.
     */
    public CompositePrivateKey(PrivateKey... keys)
    {
        this(MiscObjectIdentifiers.id_composite_key, keys);
    }

    public CompositePrivateKey(ASN1ObjectIdentifier algorithm, PrivateKey... keys)
    {
        this(new AlgorithmIdentifier(algorithm), keys);
    }

    /**
     * Create a composite private key which corresponds to a composite signature algorithm in algorithmIdentifier.
     * The component private keys are not checked if they satisfy the composite definition at this point,
     * however, they will fail when they are fed into component algorithms which are defined by the algorithmIdentifier.
     *
     * @param algorithmIdentifier
     * @param keys
     */
    public CompositePrivateKey(AlgorithmIdentifier algorithmIdentifier, PrivateKey... keys)
    {
        this.algorithmIdentifier = algorithmIdentifier;

        if (keys == null || keys.length == 0)
        {
            throw new IllegalArgumentException("at least one private key must be provided for the composite private key");
        }

        List<PrivateKey> keyList = new ArrayList<PrivateKey>(keys.length);
        for (int i = 0; i < keys.length; i++)
        {
            keyList.add(processKey(keys[i]));
        }
        this.keys = Collections.unmodifiableList(keyList);
        this.providers = null;
    }

    private PrivateKey processKey(PrivateKey key)
    {
        // we assume this also means BCKey
        if (key instanceof MLDSAPrivateKey)
        {
            // TODO: we don't insist on seed but we try to accommodate it - the debate continues
            try
            {
                return ((MLDSAPrivateKey)key).getPrivateKey(true);
            }
            catch (Exception e)
            {
                return key;
            }
        }
        else
        {
            return key;
        }
    }

    private CompositePrivateKey(AlgorithmIdentifier algorithmIdentifier, PrivateKey[] keys, Provider[] providers)
    {
        this.algorithmIdentifier = algorithmIdentifier;

        if (keys.length != 2)
        {
            throw new IllegalArgumentException("two keys required for composite private key");
        }

        List<PrivateKey> keyList = new ArrayList<PrivateKey>(keys.length);
        if (providers == null)
        {
            for (int i = 0; i < keys.length; i++)
            {
                keyList.add(processKey(keys[i]));
            }
            this.providers = null;
        }
        else
        {
            List<Provider> providerList = new ArrayList<Provider>(providers.length);
            for (int i = 0; i < keys.length; i++)
            {
                providerList.add(providers[i]);
                keyList.add(processKey(keys[i]));
            }
            this.providers = Collections.unmodifiableList(providerList);
        }
        this.keys = Collections.unmodifiableList(keyList);

    }

    /**
     * Create a composite private key from a PrivateKeyInfo.
     *
     * @param keyInfo PrivateKeyInfo object containing a composite private key.
     */
    public CompositePrivateKey(PrivateKeyInfo keyInfo)
    {
        CompositePrivateKey privateKeyFromFactory = null;
        ASN1ObjectIdentifier keyInfoIdentifier = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        try
        {
            if (!CompositeIndex.isAlgorithmSupported(keyInfoIdentifier))
            {
                throw new IllegalStateException("Unable to create CompositePrivateKey from PrivateKeyInfo");
            }
            AsymmetricKeyInfoConverter keyInfoConverter = new KeyFactorySpi();
            privateKeyFromFactory = (CompositePrivateKey)keyInfoConverter.generatePrivate(keyInfo);

            if (privateKeyFromFactory == null)
            {
                throw new IllegalStateException("Unable to create CompositePrivateKey from PrivateKeyInfo");
            }
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }

        this.keys = privateKeyFromFactory.getPrivateKeys();
        this.providers = null;
        this.algorithmIdentifier = privateKeyFromFactory.getAlgorithmIdentifier();
    }

    /**
     * Return a list of the component private keys making up this composite.
     *
     * @return an immutable list of private keys.
     */
    public List<PrivateKey> getPrivateKeys()
    {
        return keys;
    }

    /**
     * Return a list of the providers supporting the component private keys.
     *
     * @return an immutable list of Provider objects.
     */
    public List<Provider> getProviders()
    {
        return providers;
    }

    public String getAlgorithm()
    {
        return CompositeIndex.getAlgorithmName(this.algorithmIdentifier.getAlgorithm());
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Returns the encoding of the composite private key.
     * It is compliant with <a href="https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html">
     * Composite ML-DSA for use in X.509 Public Key Infrastructure</a>
     * as each component is encoded as a PrivateKeyInfo (older name for OneAsymmetricKey).
     *
     * @return
     */
    public byte[] getEncoded()
    {
        ASN1ObjectIdentifier algOid = algorithmIdentifier.getAlgorithm();

        if (algOid.on(IANAObjectIdentifiers.id_alg))
        {
            try
            {
                PrivateKey key0 = keys.get(0);
                PrivateKey key1 = keys.get(1);

                byte[] mldsaSeed = ((MLDSAPrivateKey)key0).getSeed();

                PrivateKeyInfo pki = PrivateKeyInfo.getInstance(key1.getEncoded());

                byte[] tradSK;
                String key1Algorithm = key1.getAlgorithm();
                if (key1Algorithm.contains("Ed"))
                {
                    tradSK = ASN1OctetString.getInstance(pki.parsePrivateKey()).getOctets();
                }
                else if (key1Algorithm.contains("EC"))
                {
                    ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(pki.parsePrivateKey());

                    /*
                     * TODO
                     * - Confirm pki.privateKeyAlgorithm is id_ecPublicKey with X9.62 Parameters namedCurve OID.
                     * - If ecPrivateKey.parameters are present, must match pki.privateKeyAlgorithm
                     * The private key MUST be encoded as ECPrivateKey specified in [RFC5915] with the 'NamedCurve'
                     * parameter set to the OID of the curve, but without the 'publicKey' field.
                     */
                    // TODO Also need to ensure that ECPrivateKey.parameters are present
                    ASN1BitString publicKey = ecPrivateKey.getPublicKey();
                    if (publicKey != null)
                    {
                        ecPrivateKey = new ECPrivateKey(ecPrivateKey.getPrivateKey(), ecPrivateKey.getParametersObject(), null);
                    }

                    tradSK = ecPrivateKey.getEncoded(ASN1Encoding.DER);
                }
                else
                {
                    tradSK = pki.getPrivateKey().getOctets();
                }

                return new PrivateKeyInfo(algorithmIdentifier, Arrays.concatenate(mldsaSeed, tradSK)).getEncoded();
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to encode composite public key: " + e.getMessage());
            }
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        if (MiscObjectIdentifiers.id_composite_key.equals(algOid))
        {
            for (int i = 0; i < keys.size(); i++)
            {
                PrivateKeyInfo pki = PrivateKeyInfo.getInstance(keys.get(i).getEncoded());

                v.add(pki);
            }

            try
            {
                return new PrivateKeyInfo(this.algorithmIdentifier, new DERSequence(v)).getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to encode composite private key: " + e.getMessage());
            }
        }
        else
        {
            byte[] keyEncoding = null;
            for (int i = 0; i < keys.size(); i++)
            {
                PrivateKeyInfo pki = PrivateKeyInfo.getInstance(keys.get(i).getEncoded());

                keyEncoding = Arrays.concatenate(keyEncoding, pki.getPrivateKey().getOctets());
            }

            try
            {
                return new PrivateKeyInfo(this.algorithmIdentifier, keyEncoding).getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to encode composite private key: " + e.getMessage());
            }
        }
    }

    public int hashCode()
    {
        return keys.hashCode();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof CompositePrivateKey)
        {
            boolean isEqual = true;
            CompositePrivateKey comparedKey = (CompositePrivateKey)o;
            if (!comparedKey.getAlgorithmIdentifier().equals(this.algorithmIdentifier) || !this.keys.equals(comparedKey.keys))
            {
                isEqual = false;
            }

            return isEqual;
        }

        return false;
    }
}
