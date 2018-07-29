package org.bouncycastle.mime;

import java.io.IOException;
import java.io.InputStream;

public interface MimeParserProvider
{
    MimeParser createParser(InputStream source)
        throws IOException;

    MimeParser createParser(Headers headers, InputStream source)
        throws IOException;
}
