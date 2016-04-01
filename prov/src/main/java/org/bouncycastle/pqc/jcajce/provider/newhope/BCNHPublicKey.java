package org.bouncycastle.pqc.jcajce.provider.newhope;

import java.io.IOException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.NHPublicKey;
import org.bouncycastle.util.Arrays;

public class BCNHPublicKey
    implements NHPublicKey
{
    private static final long serialVersionUID = 1L;

    private final NHPublicKeyParameters params;

    public BCNHPublicKey(
        NHPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCNHPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        this.params = new NHPublicKeyParameters(keyInfo.getPublicKeyData().getBytes());
    }

    /**
     * Compare this SPHINCS-256 public key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == null || !(o instanceof BCNHPublicKey))
        {
            return false;
        }
        BCNHPublicKey otherKey = (BCNHPublicKey)o;

        return Arrays.areEqual(params.getPubData(), otherKey.params.getPubData());
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getPubData());
    }

    /**
     * @return name of the algorithm - "NH"
     */
    public final String getAlgorithm()
    {
        return "NH";
    }

    public byte[] getEncoded()
    {
        SubjectPublicKeyInfo pki;
        try
        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            pki = new SubjectPublicKeyInfo(algorithmIdentifier, params.getPubData());

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getPublicData()
    {
        return params.getPubData();
    }

    CipherParameters getKeyParams()
    {
        return params;
    }
}
