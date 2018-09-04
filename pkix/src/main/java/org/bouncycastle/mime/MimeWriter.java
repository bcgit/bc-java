package org.bouncycastle.mime;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public abstract class MimeWriter
{
    protected final Headers headers;

    protected MimeWriter(Headers headers)
    {
        this.headers = headers;
    }

    public Headers getHeaders()
    {
        return headers;
    }

    public abstract OutputStream getContentStream()
        throws IOException;


    protected static List<String> mapToLines(Map<String, String> headers)
    {
        List hdrs = new ArrayList(headers.size());

        for (Iterator<String> it = headers.keySet().iterator(); it.hasNext();)
        {
            String key = (String)it.next();

            hdrs.add(key + ": " + headers.get(key));
        }

        return hdrs;
    }
}
