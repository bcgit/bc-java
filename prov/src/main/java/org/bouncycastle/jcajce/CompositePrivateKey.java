package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
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
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * A composite private key class for Composite ML-KEM.
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
        return builder(CompositeUtil.getOid(algorithmName)); // UPDATED: Use KEM util
    }

    private final List<PrivateKey> keys;
    private final List<Provider> providers;

    private AlgorithmIdentifier algorithmIdentifier;

    /**
     * Create a composite private key from an array of PrivateKeys.
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
     * Create a composite private key which corresponds to a composite KEM algorithm in algorithmIdentifier.
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
        CompositePrivateKey privateKeyFromFactory;
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
        return CompositeIndex.getAlgorithmName(this.algorithmIdentifier.getAlgorithm()); // UPDATED
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
     * Returns the encoding of the composite private key as per Section 4.2.
     * Format: ML-KEM seed (64 bytes) || Traditional private key encoding
     */
    public byte[] getEncoded()
    {
        ASN1ObjectIdentifier algOid = algorithmIdentifier.getAlgorithm();

        if (org.bouncycastle.jcajce.provider.asymmetric.compositekem.CompositeIndex.isCompositeKEMOID(algOid))
        {
            try
            {
                PrivateKey mlkemKey = keys.get(0);
                PrivateKey tradKey = keys.get(1);

                // 1. Get ML-KEM seed (64 bytes) as per Section 4.2
                byte[] mlkemSeed;
                if (mlkemKey instanceof MLKEMPrivateKey)
                {
                    MLKEMPrivateKey mlkemPriv = (MLKEMPrivateKey)mlkemKey;
                    mlkemSeed = mlkemPriv.getSeed();
                    if (mlkemSeed == null || mlkemSeed.length != 64)
                    {
                        throw new IllegalStateException("ML-KEM private key must provide a 64-byte seed");
                    }
                }
                else
                {
                    // Try to extract from encoded form
                    PrivateKeyInfo pki = PrivateKeyInfo.getInstance(mlkemKey.getEncoded());
                    mlkemSeed = pki.getPrivateKey().getOctets();
                    if (mlkemSeed.length != 64)
                    {
                        throw new IllegalStateException("ML-KEM private key must be 64-byte seed");
                    }
                }

                byte[] tradSK = encodeTraditionalPrivateKey(tradKey);

                byte[] compositePrivateBytes = Arrays.concatenate(mlkemSeed, tradSK);

                return new PrivateKeyInfo(algorithmIdentifier, compositePrivateBytes).getEncoded();
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to encode composite private key: " + e.getMessage(), e);
            }
        }
        else if (algOid.on(IANAObjectIdentifiers.id_alg))
        {
            try
            {
                PrivateKey key0 = keys.get(0);
                PrivateKey key1 = keys.get(1);

                byte[] mldsaSeed = ((org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey)key0).getSeed();

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
                throw Exceptions.illegalStateException("unable to encode composite public key", e);
            }
        }
        else
        {
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
                    throw Exceptions.illegalStateException("unable to encode composite private key", e);
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
                    throw Exceptions.illegalStateException("unable to encode composite private key", e);
                }
            }
        }
    }

    /**
     * Encode traditional private key as per Section 4.2
     */
    private byte[] encodeTraditionalPrivateKey(PrivateKey key) throws IOException
    {
        String algorithm = key.getAlgorithm();

        if (algorithm.contains("RSA"))
        {
            // RSA: RSAPrivateKey with version 0, no otherPrimeInfos
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(key.getEncoded());
            // Verify it's correct format
            return pki.getPrivateKey().getOctets();
        }
        else if (algorithm.contains("EC"))
        {
            // ECDH: ECPrivateKey without publicKey field
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(key.getEncoded());
            ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(pki.parsePrivateKey());

            // Remove publicKey field if present
            if (ecPrivateKey.getPublicKey() != null)
            {
                ecPrivateKey = new ECPrivateKey(ecPrivateKey.getPrivateKey(),
                    ecPrivateKey.getParametersObject(), null);
            }

            return ecPrivateKey.getEncoded(ASN1Encoding.DER);
        }
        else if (algorithm.contains("X25519") || algorithm.contains("X448"))
        {
            // X25519/X448: raw 32/56 byte value
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(key.getEncoded());
            return ASN1OctetString.getInstance(pki.parsePrivateKey()).getOctets();
        }

        throw new IOException("Unsupported traditional algorithm: " + algorithm);
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