package org.bouncycastle.crypto.parsers;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.io.Streams;

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
        int first = stream.read();
        if (first < 0)
        {
            throw new EOFException();
        }

        // Decode the public ephemeral key
        boolean compressed;
        switch (first)
        {
        case 0x00: // infinity
            throw new IOException("Sender's public key invalid.");

        case 0x02: // compressed
        case 0x03: // Byte length calculated as in ECPoint.getEncoded();
            compressed = true;
            break;

        case 0x04: // uncompressed or
        case 0x06: // hybrid
        case 0x07: // Byte length calculated as in ECPoint.getEncoded();
            compressed = false;
            break;

        default:
            throw new IOException("Sender's public key has invalid point encoding 0x" + Integer.toString(first, 16));
        }

        ECCurve curve = ecParams.getCurve();
        int encodingLength = curve.getAffinePointEncodingLength(compressed);
        byte[] V = new byte[encodingLength];
        V[0] = (byte)first;

        int readLength = encodingLength - 1;
        if (Streams.readFully(stream, V, 1, readLength) != readLength)
        {
            throw new EOFException();
        }

        return new ECPublicKeyParameters(curve.decodePoint(V), ecParams);
    }
}
