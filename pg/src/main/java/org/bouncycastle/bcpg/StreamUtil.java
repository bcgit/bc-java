package org.bouncycastle.bcpg;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;

class StreamUtil
{
    private static final long  MAX_MEMORY = Runtime.getRuntime().maxMemory();

    /**
     * Find out possible longest length, capped by available memory.
     *
     * @param in input stream of interest
     * @return length calculation or MAX_VALUE.
     */
    static int findLimit(InputStream in)
    {
        // TODO: this can obviously be improved.
        if (in instanceof ByteArrayInputStream)
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

        if (MAX_MEMORY > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }

        return (int)MAX_MEMORY;
    }
}
