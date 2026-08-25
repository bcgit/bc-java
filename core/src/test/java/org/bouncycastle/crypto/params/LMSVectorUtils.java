package org.bouncycastle.crypto.params;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

public class LMSVectorUtils
{
    public static final byte[] extract$PrefixedBytes(String vectorFromRFC)
        throws Exception
    {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (String line : vectorFromRFC.split("\n"))
        {
            int start = line.indexOf("$");
            if (start > -1)
            {

                int end = line.indexOf("#");
                String hex;
                if (end < 0)
                {
                    hex = line.substring(start + 1).trim();
                }
                else
                {
                    hex = line.substring(start + 1, end).trim();
                }

                bos.write(Hex.decode(hex));
            }
        }
        return bos.toByteArray();

    }

    /**
     * A builder for the RFC 8554 sec. 3.1 encodings the tests assemble by hand.
     */
    public static Encoder compose()
    {
        return new Encoder();
    }

    public static class Encoder
    {
        private final ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        public Encoder u32str(int n)
        {
            bOut.write(Pack.intToBigEndian(n), 0, 4);
            return this;
        }

        public Encoder u64str(long n)
        {
            bOut.write(Pack.longToBigEndian(n), 0, 8);
            return this;
        }

        public Encoder bool(boolean v)
        {
            bOut.write(v ? 1 : 0);
            return this;
        }

        public Encoder bytes(byte[] data)
        {
            bOut.write(data, 0, data.length);
            return this;
        }

        public byte[] build()
        {
            return bOut.toByteArray();
        }
    }
}
