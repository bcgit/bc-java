package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * A composite private key class.
 */
public class CompositePrivateKey
    implements PrivateKey
{
    private final List<PrivateKey> keys;

    private ASN1ObjectIdentifier algorithmIdentifier;

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

    /**
     * Create a composite private key which corresponds to a composite signature algorithm in algorithmIdentifier.
     * The component private keys are not checked if they satisfy the composite definition at this point,
     * however, they will fail when they are fed into component algorithms which are defined by the algorithmIdentifier.
     *
     * @param algorithmIdentifier
     * @param keys
     */
    public CompositePrivateKey(ASN1ObjectIdentifier algorithmIdentifier, PrivateKey... keys)
    {
        this.algorithmIdentifier = algorithmIdentifier;

        if (keys == null || keys.length == 0)
        {
            throw new IllegalArgumentException("at least one private key must be provided for the composite private key");
        }

        List<PrivateKey> keyList = new ArrayList<PrivateKey>(keys.length);
        for (int i = 0; i < keys.length; i++)
        {
            keyList.add(keys[i]);
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

    public String getAlgorithm()
    {
        return CompositeIndex.getAlgorithmName(this.algorithmIdentifier);
    }

    public ASN1ObjectIdentifier getAlgorithmIdentifier()
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
        if (this.algorithmIdentifier.on(MiscObjectIdentifiers.id_MLDSA_COMPSIG))
        {
            try
            {
                byte[] mldsaKey = ((BCMLDSAPrivateKey)keys.get(0)).getSeed();
                PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(PrivateKeyFactory.createKey(keys.get(1).getEncoded()));
                byte[] tradKey = pki.getPrivateKey().getOctets();
                return Arrays.concatenate(mldsaKey, tradKey);
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to encode composite public key: " + e.getMessage());
            }
        }
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (algorithmIdentifier.equals(MiscObjectIdentifiers.id_composite_key))
        {
            for (int i = 0; i < keys.size(); i++)
            {
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(keys.get(i).getEncoded());
                v.add(info);
            }

            try
            {
                return new PrivateKeyInfo(new AlgorithmIdentifier(this.algorithmIdentifier), new DERSequence(v)).getEncoded(ASN1Encoding.DER);
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
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(keys.get(i).getEncoded());
                keyEncoding = Arrays.concatenate(keyEncoding, info.getPrivateKey().getOctets());
            }

            try
            {
                return new PrivateKeyInfo(new AlgorithmIdentifier(this.algorithmIdentifier), keyEncoding).getEncoded(ASN1Encoding.DER);
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
