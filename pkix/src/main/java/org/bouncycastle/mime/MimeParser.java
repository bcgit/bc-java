package org.bouncycastle.mime;

import java.io.IOException;

/**
 * Base interface for a MIME parser.
 */
public interface MimeParser
{
    /**
     * Trigger the start of parsing.
     *
     * @param listener callback to be signalled as each MIME object is identified.
     * @throws IOException on a parsing/IO exception.
     */
    void parse(MimeParserListener listener)
        throws IOException;
}