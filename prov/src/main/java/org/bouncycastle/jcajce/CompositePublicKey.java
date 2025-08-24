package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.util.Arrays;

/**
 * A composite key class.
 */
public class CompositePublicKey
    implements PublicKey
{
    public static class Builder
    {
        private final AlgorithmIdentifier algorithmIdentifier;
        private final PublicKey[] keys = new PublicKey[2];
        private final Provider[] providers = new Provider[2];

        private int count = 0;

        private Builder(AlgorithmIdentifier algorithmIdentifier)
        {
            this.algorithmIdentifier = algorithmIdentifier;
        }

        public Builder addPublicKey(PublicKey key)
        {
            return addPublicKey(key, (Provider)null);
        }

        public Builder addPublicKey(PublicKey key, String providerName)
        {
            return addPublicKey(key, Security.getProvider(providerName));
        }

        public Builder addPublicKey(PublicKey key, Provider provider)
        {
            if (count == keys.length)
            {
                throw new IllegalStateException("only " + keys.length + " allowed in composite");
            }

            keys[count] = key;
            providers[count++] = provider;

            return this;
        }

        public CompositePublicKey build()
        {
            if (providers[0] == null && providers[1] == null)
            {
                return new CompositePublicKey(algorithmIdentifier, keys, null);
            }

            return new CompositePublicKey(algorithmIdentifier, keys, providers);
        }
    }

    public static Builder builder(ASN1ObjectIdentifier compAlgOid)
    {
        return new Builder(new AlgorithmIdentifier(compAlgOid));
    }

    private final List<PublicKey> keys;
    private final List<Provider> providers;

    private final AlgorithmIdentifier algorithmIdentifier;

    /**
     * Create a composite public key from an array of PublicKeys.
     * This constructor is currently used only for legacy composites implementation.
     *
     * @param keys The component public keys.
     */
    public CompositePublicKey(PublicKey... keys)
    {
        this(MiscObjectIdentifiers.id_composite_key, keys);
    }

    public CompositePublicKey(ASN1ObjectIdentifier algorithmIdentifier, PublicKey... keys)
    {
        this(new AlgorithmIdentifier(algorithmIdentifier), keys);
    }

    /**
     * Create a composite public key which corresponds to a composite signature algorithm in algorithmIdentifier.
     * The component public keys are not checked if they satisfy the composite definition at this point,
     * however, they will fail when they are fed into component algorithms which are defined by the algorithmIdentifier.
     *
     * @param algorithmIdentifier
     * @param keys
     */
    public CompositePublicKey(AlgorithmIdentifier algorithmIdentifier, PublicKey... keys)
    {
        this.algorithmIdentifier = algorithmIdentifier;

        if (keys == null || keys.length == 0)
        {
            throw new IllegalArgumentException("at least one public key must be provided for the composite public key");
        }

        List<PublicKey> keyList = new ArrayList<PublicKey>(keys.length);
        for (int i = 0; i < keys.length; i++)
        {
            keyList.add(keys[i]);
        }
        this.keys = Collections.unmodifiableList(keyList);
        this.providers = null;
    }

    /**
     * Create a composite public key from a SubjectPublicKeyInfo.
     *
     * @param keyInfo SubjectPublicKeyInfo object containing a composite public key.
     */
    public CompositePublicKey(SubjectPublicKeyInfo keyInfo)
    {
        ASN1ObjectIdentifier keyInfoIdentifier = keyInfo.getAlgorithm().getAlgorithm();
        CompositePublicKey publicKeyFromFactory = null;
        try
        {
            //Check if the public key algorithm specified in SubjectPublicKeyInfo is one of the supported composite signatures.
            if (!CompositeIndex.isAlgorithmSupported(keyInfoIdentifier))
            {
                throw new IllegalStateException("unable to create CompositePublicKey from SubjectPublicKeyInfo");
            }
            AsymmetricKeyInfoConverter keyInfoConverter = new KeyFactorySpi();
            publicKeyFromFactory = (CompositePublicKey)keyInfoConverter.generatePublic(keyInfo);

            if (publicKeyFromFactory == null)
            {
                throw new IllegalStateException("unable to create CompositePublicKey from SubjectPublicKeyInfo");
            }
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }

        this.keys = publicKeyFromFactory.getPublicKeys();
        this.algorithmIdentifier = publicKeyFromFactory.getAlgorithmIdentifier();
        this.providers = null;
    }

    private CompositePublicKey(AlgorithmIdentifier algorithmIdentifier, PublicKey[] keys, Provider[] providers)
    {
        this.algorithmIdentifier = algorithmIdentifier;

        if (keys.length != 2)
        {
            throw new IllegalArgumentException("two keys required for composite private key");
        }

        List<PublicKey> keyList = new ArrayList<PublicKey>(keys.length);
        if (providers == null)
        {
            for (int i = 0; i < keys.length; i++)
            {
                keyList.add(keys[i]);
            }
            this.providers = null;
        }
        else
        {
            List<Provider> providerList = new ArrayList<Provider>(providers.length);
            for (int i = 0; i < keys.length; i++)
            {
                providerList.add(providers[i]);
                keyList.add(keys[i]);
            }
            this.providers = Collections.unmodifiableList(providerList);
        }
        this.keys = Collections.unmodifiableList(keyList);
    }

    /**
     * Return a list of the component public keys making up this composite.
     *
     * @return an immutable list of public keys.
     */
    public List<PublicKey> getPublicKeys()
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
        return "X.509";
    }

    /**
     * Returns the composite public key encoded as a SubjectPublicKeyInfo.
     * If the composite public key is legacy (MiscObjectIdentifiers.id_composite_key),
     * it each component public key is wrapped in its own SubjectPublicKeyInfo.
     * Other composite public keys are encoded according to
     * <a href="https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html">
     * Composite ML-DSA for use in X.509 Public Key Infrastructure</a>
     * where each component public key is a BIT STRING which contains the result of calling
     * getEncoded() for each component public key.
     *
     * @return
     */
    @Override
    public byte[] getEncoded()
    {
        if (this.algorithmIdentifier.getAlgorithm().on(MiscObjectIdentifiers.id_MLDSA_COMPSIG))
        {
            try
            {
                byte[] mldsaKey = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(keys.get(0).getEncoded())).getPublicKeyData().getBytes();
                byte[] tradKey = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(PublicKeyFactory.createKey(keys.get(1).getEncoded())).getPublicKeyData().getBytes();
                return new SubjectPublicKeyInfo(getAlgorithmIdentifier(), Arrays.concatenate(mldsaKey, tradKey)).getEncoded();
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to encode composite public key: " + e.getMessage());
            }
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i < keys.size(); i++)
        {
            if (this.algorithmIdentifier.getAlgorithm().equals(MiscObjectIdentifiers.id_composite_key))
            {
                //Legacy, component is the whole SubjectPublicKeyInfo
                v.add(SubjectPublicKeyInfo.getInstance(keys.get(i).getEncoded()));
            }
            else
            {
                //component is the value of subjectPublicKey from SubjectPublicKeyInfo
                SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.get(i).getEncoded());
                v.add(keyInfo.getPublicKeyData());
            }
        }
        try
        {
            return new SubjectPublicKeyInfo(this.algorithmIdentifier, new DERSequence(v)).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode composite public key: " + e.getMessage());
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

        if (o instanceof CompositePublicKey)
        {
            boolean isEqual = true;
            CompositePublicKey comparedKey = (CompositePublicKey)o;
            if (!comparedKey.getAlgorithmIdentifier().equals(this.algorithmIdentifier) || !this.keys.equals(comparedKey.keys))
            {
                isEqual = false;
            }

            return isEqual;
        }

        return false;
    }
}
