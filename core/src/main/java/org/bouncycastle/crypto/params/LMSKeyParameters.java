package org.bouncycastle.crypto.params;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

public abstract class LMSKeyParameters
    extends AsymmetricKeyParameter
    implements Encodable
{
    protected LMSKeyParameters(boolean isPrivateKey)
    {
        super(isPrivateKey);
    }

    abstract public byte[] getEncoded()
        throws IOException;

    //
    // The RFC 8554 sec. 3.1 encoding primitives the key classes build their encodings from.
    //

    static void u32str(int n, ByteArrayOutputStream out)
    {
        out.write(Pack.intToBigEndian(n), 0, 4);
    }

    static void u64str(long n, ByteArrayOutputStream out)
    {
        out.write(Pack.longToBigEndian(n), 0, 8);
    }

    static void bytes(byte[] data, ByteArrayOutputStream out)
    {
        out.write(data, 0, data.length);
    }
}
