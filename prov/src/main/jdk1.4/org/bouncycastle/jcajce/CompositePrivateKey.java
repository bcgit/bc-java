package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * A composite private key class.
 */
public class CompositePrivateKey
    implements PrivateKey
{
    private final List<PrivateKey> keys;

    /**
     * Create a composite key containing a single private key.
     *
     * @param keys the private keys the composite private key wraps.
     */
    public CompositePrivateKey(PrivateKey[] keys)
    {
        if (keys == null || keys.length == 0)
        {
            throw new IllegalArgumentException("at least one public key must be provided");
        }

        List<PrivateKey> keyList = new ArrayList<PrivateKey>(keys.length);
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
    public List<PrivateKey> getPrivateKeys()
    {
        return keys;
    }

    public String getAlgorithm()
    {
        return "Composite";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != keys.size(); i++)
        {
            v.add(PrivateKeyInfo.getInstance(((PrivateKey)keys.get(i)).getEncoded()));
        }

        try
        {
            return new PrivateKeyInfo(
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

        if (o instanceof CompositePrivateKey)
        {
            return keys.equals(((CompositePrivateKey)o).keys);
        }

        return false;
    }
}
