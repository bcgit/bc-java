package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

/**
 * A composite key class.
 */
public class CompositePublicKey implements PublicKey
{
    private final List<PublicKey> keys;

    private final ASN1ObjectIdentifier algorithmIdentifier;

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

    /**
     * Create a composite public key which corresponds to a composite signature algorithm in algorithmIdentifier.
     * The component public keys are not checked if they satisfy the composite definition at this point,
     * however, they will fail when they are fed into component algorithms which are defined by the algorithmIdentifier.
     *
     * @param algorithmIdentifier
     * @param keys
     */
    public CompositePublicKey(ASN1ObjectIdentifier algorithmIdentifier, PublicKey... keys)
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
            if (!Arrays.asList(CompositeSignaturesConstants.supportedIdentifiers).contains(keyInfoIdentifier))
            {
                throw new IllegalStateException("unable to create CompositePublicKey from SubjectPublicKeyInfo");
            }
            AsymmetricKeyInfoConverter keyInfoConverter = new KeyFactorySpi();
            publicKeyFromFactory = (CompositePublicKey) keyInfoConverter.generatePublic(keyInfo);

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
        return "X.509";
    }

    /**
     * Returns the composite public key encoded as a SubjectPublicKeyInfo.
     * If the composite public key is legacy (MiscObjectIdentifiers.id_composite_key),
     * it each component public key is wrapped in its own SubjectPublicKeyInfo.
     * Other composite public keys are encoded according to https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html#name-compositesignaturepublickey
     * where each component public key is a BIT STRING which contains the result of calling
     * getEncoded() for each component public key.
     *
     * @return
     */
    @Override
    public byte[] getEncoded()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i < keys.size(); i++)
        {
            if (this.algorithmIdentifier.equals(MiscObjectIdentifiers.id_composite_key))
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
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(this.algorithmIdentifier), new DERSequence(v)).getEncoded(ASN1Encoding.DER);
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
            CompositePublicKey comparedKey = (CompositePublicKey) o;
            if (!comparedKey.getAlgorithmIdentifier().equals(this.algorithmIdentifier) || !this.keys.equals(comparedKey.keys))
            {
                isEqual = false;
            }

            return isEqual;
        }

        return false;
    }
}
