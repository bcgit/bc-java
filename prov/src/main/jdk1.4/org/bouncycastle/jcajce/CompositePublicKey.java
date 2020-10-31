package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * A composite key class.
 */
public class CompositePublicKey
    implements PublicKey
{
    private final List<PublicKey> keys;

    /**
     * Create a composite key containing a single public key.
     *
     * @param keys the public keys the composite key wraps.
     */
    public CompositePublicKey(PublicKey[] keys)
    {
        if (keys == null || keys.length == 0)
        {
            throw new IllegalArgumentException("at least one public key must be provided");
        }

        List<PublicKey> keyList = new ArrayList<PublicKey>(keys.length);
        for (int i = 0; i != keys.length; i++)
        {
            keyList.add(keys[i]);
        }
        this.keys = Collections.unmodifiableList(keyList);
    }

    /**
     * Return a list of the component private keys making up this composite.
     *
     * @return an immutable list of private keys.
     */
    public List<PublicKey> getPublicKeys()
    {
        return keys;
    }

    public String getAlgorithm()
    {
        return "Composite";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != keys.size(); i++)
        {
            v.add(SubjectPublicKeyInfo.getInstance(((PublicKey)keys.get(i)).getEncoded()));
        }

        try
        {
            return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite), new DERSequence(v)).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode composite key: " + e.getMessage());
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
            return keys.equals(((CompositePublicKey)o).keys);
        }

        return false;
    }
}
