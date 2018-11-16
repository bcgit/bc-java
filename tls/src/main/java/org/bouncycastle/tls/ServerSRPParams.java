package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

public class ServerSRPParams
{
    protected BigInteger N, g, B;
    protected byte[] s;

    public ServerSRPParams(BigInteger N, BigInteger g, byte[] s, BigInteger B)
    {
        this.N = N;
        this.g = g;
        this.s = Arrays.clone(s);
        this.B = B;
    }

    public BigInteger getB()
    {
        return B;
    }
    
    public BigInteger getG()
    {
        return g;
    }

    public BigInteger getN()
    {
        return N;
    }

    public byte[] getS()
    {
        return s;
    }

    /**
     * Encode this {@link ServerSRPParams} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsSRPUtils.writeSRPParameter(N, output);
        TlsSRPUtils.writeSRPParameter(g, output);
        TlsUtils.writeOpaque8(s, output);
        TlsSRPUtils.writeSRPParameter(B, output);
    }

    /**
     * Parse a {@link ServerSRPParams} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link ServerSRPParams} object.
     * @throws IOException
     */
    public static ServerSRPParams parse(InputStream input) throws IOException
    {
        BigInteger N = TlsSRPUtils.readSRPParameter(input);
        BigInteger g = TlsSRPUtils.readSRPParameter(input);
        byte[] s = TlsUtils.readOpaque8(input, 1);
        BigInteger B = TlsSRPUtils.readSRPParameter(input);

        return new ServerSRPParams(N, g, s, B);
    }
}
