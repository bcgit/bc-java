package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayOutputStream;

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
}
