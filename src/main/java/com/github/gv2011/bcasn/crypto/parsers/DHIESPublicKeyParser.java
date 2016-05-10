package com.github.gv2011.bcasn.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import com.github.gv2011.bcasn.crypto.KeyParser;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;
import com.github.gv2011.bcasn.crypto.params.DHParameters;
import com.github.gv2011.bcasn.crypto.params.DHPublicKeyParameters;
import com.github.gv2011.bcasn.util.io.Streams;

public class DHIESPublicKeyParser
    implements KeyParser
{
    private DHParameters dhParams;

    public DHIESPublicKeyParser(DHParameters dhParams)
    {
        this.dhParams = dhParams;
    }

    public AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException
    {
        byte[] V = new byte[(dhParams.getP().bitLength() + 7) / 8];

        Streams.readFully(stream, V, 0, V.length);

        return new DHPublicKeyParameters(new BigInteger(1, V), dhParams);
    }
}
