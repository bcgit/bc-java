package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.util.Exceptions;

/**
 * A composite private key class.
 */
public class CompositePrivateKey implements PrivateKey
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
            if (!Arrays.asList(CompositeSignaturesConstants.supportedIdentifiers).contains(keyInfoIdentifier))
            {
                throw new IllegalStateException("Unable to create CompositePrivateKey from PrivateKeyInfo");
            }
            AsymmetricKeyInfoConverter keyInfoConverter = new KeyFactorySpi();
            privateKeyFromFactory = (CompositePrivateKey) keyInfoConverter.generatePrivate(keyInfo);

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
        return CompositeSignaturesConstants.ASN1IdentifierAlgorithmNameMap.get(this.algorithmIdentifier).getId();
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
     * It is compliant with https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html#name-compositesignatureprivateke
     * as each component is encoded as a PrivateKeyInfo (older name for OneAsymmetricKey).
     *
     * @return
     */
    public byte[] getEncoded()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i < keys.size(); i++)
        {
            v.add(PrivateKeyInfo.getInstance(keys.get(i).getEncoded()));
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
            CompositePrivateKey comparedKey = (CompositePrivateKey) o;
            if (!comparedKey.getAlgorithmIdentifier().equals(this.algorithmIdentifier) || !this.keys.equals(comparedKey.keys))
            {
                isEqual = false;
            }

            return isEqual;
        }

        return false;
    }
}
