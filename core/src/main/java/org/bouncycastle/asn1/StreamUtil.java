package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;

import org.bouncycastle.util.Properties;

class StreamUtil
{
    private static final String MAX_CONS_DEPTH = "org.bouncycastle.asn1.max_cons_depth";
    private static final String MAX_LIMIT = "org.bouncycastle.asn1.max_limit";

    static void checkLength(int length, int limit) throws IOException
    {
        if (length > limit)
        {
            throw new ASN1Exception("corrupted stream - out of bounds length found: " + length + " > " + limit);
        }
    }

    static int decrementDepth(int parentDepth) throws IOException
    {
        if (parentDepth <= 0)
            throw new ASN1Exception("maximum nested construction level reached");
        return parentDepth - 1;
    }

    static int findDepth()
    {
        return Math.max(0, Properties.asInteger(MAX_CONS_DEPTH, 64));
    }

    /**
     * Find out possible longest length, capped by available memory.
     *
     * @param in input stream of interest
     * @return length calculation or MAX_VALUE.
     */
    static int findLimit(InputStream in)
    {
        if (in instanceof LimitedInputStream)
        {
            return ((LimitedInputStream)in).getLimit();
        }
        else if (in instanceof ASN1InputStream)
        {
            return ((ASN1InputStream)in).getLimit();
        }
        else if (in instanceof ByteArrayInputStream)
        {
            return ((ByteArrayInputStream)in).available();
        }
        else if (in instanceof FileInputStream)
        {
            try
            {
                FileChannel channel = ((FileInputStream)in).getChannel();
                long  size = (channel != null) ? channel.size() : Integer.MAX_VALUE;

                if (size < Integer.MAX_VALUE)
                {
                    return (int)size;
                }
            }
            catch (IOException e)
            {
                // ignore - they'll find out soon enough!
            }
        }

        String limit = Properties.getPropertyValue(MAX_LIMIT);
        if (limit != null)
        {
            switch (limit.charAt(limit.length() - 1))
            {
            case 'k':
                return Integer.parseInt(limit.substring(0, limit.length() - 1)) * 1024;
            case 'm':
                return Integer.parseInt(limit.substring(0, limit.length() - 1)) * 1024 * 1024;
            case 'g':
                return Integer.parseInt(limit.substring(0, limit.length() - 1)) * 1024 * 1024 * 1024;
            default:
                return Integer.parseInt(limit);
            }
        }

        return getMaxMemory();
    }

    private static int getMaxMemory()
    {
        long maxMemory = Runtime.getRuntime().maxMemory();
        if (maxMemory > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }
        return (int)maxMemory;
    }
}
