package org.bouncycastle.mime;

import java.io.IOException;
import java.io.InputStream;

public class ConstantMimeContext
    implements MimeContext, MimeMultipartContext
{
    public InputStream applyContext(Headers headers, InputStream contentStream)
        throws IOException
    {
        return contentStream;
    }

    public MimeContext createContext(int partNo)
        throws IOException
    {
        return this;
    }
}
