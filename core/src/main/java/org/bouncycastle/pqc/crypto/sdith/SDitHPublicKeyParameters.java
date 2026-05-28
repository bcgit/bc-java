package org.bouncycastle.pqc.crypto.sdith;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SDitHPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final SDitHParameters parameters;
    private final byte[] hASeed;
    private final byte[] y;

    public SDitHPublicKeyParameters(SDitHParameters parameters, byte[] hASeed, byte[] y)
    {
        super(false);
        if (hASeed == null || y == null)
        {
            throw new NullPointerException("hASeed and y must not be null");
        }
        if (hASeed.length != parameters.getSeedSize())
        {
            throw new IllegalArgumentException("hASeed length mismatch");
        }
        if (y.length != parameters.getYSize())
        {
            throw new IllegalArgumentException("y length mismatch");
        }
        this.parameters = parameters;
        this.hASeed = Arrays.clone(hASeed);
        this.y = Arrays.clone(y);
    }

    public SDitHPublicKeyParameters(SDitHParameters parameters, byte[] encoded)
    {
        super(false);
        int seedSize = parameters.getSeedSize();
        int ySize = parameters.getYSize();
        if (encoded.length != seedSize + ySize)
        {
            throw new IllegalArgumentException("encoded length mismatch");
        }
        this.parameters = parameters;
        this.hASeed = Arrays.copyOfRange(encoded, 0, seedSize);
        this.y = Arrays.copyOfRange(encoded, seedSize, encoded.length);
    }

    public SDitHParameters getParameters()
    {
        return parameters;
    }

    public byte[] getHASeed()
    {
        return Arrays.clone(hASeed);
    }

    public byte[] getY()
    {
        return Arrays.clone(y);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(hASeed, y);
    }
}
