package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

class StreamUtil
{
    /**
     * Find out possible longest length...
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

        return Integer.MAX_VALUE;
    }
}
