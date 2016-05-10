package com.github.gv2011.bcasn.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;

import com.github.gv2011.bcasn.crypto.KeyParser;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;
import com.github.gv2011.bcasn.crypto.params.ECDomainParameters;
import com.github.gv2011.bcasn.crypto.params.ECPublicKeyParameters;
import com.github.gv2011.bcasn.util.io.Streams;

public class ECIESPublicKeyParser
    implements KeyParser
{
    private ECDomainParameters ecParams;

    public ECIESPublicKeyParser(ECDomainParameters ecParams)
    {
        this.ecParams = ecParams;
    }

    public AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException
    {
        byte[] V;
        int    first = stream.read();

        // Decode the public ephemeral key
        switch (first)
        {
        case 0x00: // infinity
            throw new IOException("Sender's public key invalid.");

        case 0x02: // compressed
        case 0x03: // Byte length calculated as in ECPoint.getEncoded();
            V = new byte[1 + (ecParams.getCurve().getFieldSize()+7)/8];
            break;

        case 0x04: // uncompressed or
        case 0x06: // hybrid
        case 0x07: // Byte length calculated as in ECPoint.getEncoded();
            V = new byte[1 + 2*((ecParams.getCurve().getFieldSize()+7)/8)];
            break;

        default:
            throw new IOException("Sender's public key has invalid point encoding 0x" + Integer.toString(first, 16));
        }

        V[0] = (byte)first;
        Streams.readFully(stream, V, 1, V.length - 1);

        return new ECPublicKeyParameters(ecParams.getCurve().decodePoint(V), ecParams);
    }
}
