package org.bouncycastle.mime;

import java.io.IOException;
import java.io.InputStream;

/**
 * Base interface for a MIME parser listener.
 */
public interface MimeParserListener
{
    /**
     * Create an appropriate context object for the MIME object represented by headers.
     *
     * @param parserContext context object for the current parser.
     * @param headers MIME headers for the object that has been discovered.
     * @return a MimeContext
     */
    MimeContext createContext(MimeParserContext parserContext, Headers headers);

    /**
     * Signal that a MIME object has been discovered.
     *
     * @param parserContext context object for the current parser.
     * @param headers headers for the MIME object.
     * @param inputStream input stream representing its content.
     * @throws IOException in case of a parsing/processing error.
     */
    void object(MimeParserContext parserContext, Headers headers, InputStream inputStream)
        throws IOException;
}
