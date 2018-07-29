package org.bouncycastle.mime;

/**
 * Base interface for a MIME parser context.
 */
public interface MimeParserContext
{
    /**
     * Return the default value for Content-Transfer-Encoding for data we are parsing.
     *
     * @return the default Content-Transfer-Encoding.
     */
    String getDefaultContentTransferEncoding();
}
