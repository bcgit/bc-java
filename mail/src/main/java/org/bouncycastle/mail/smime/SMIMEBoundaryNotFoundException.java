package org.bouncycastle.mail.smime;

import javax.mail.MessagingException;

/**
 * MessagingException thrown when the raw content of a multipart body part
 * does not contain the expected number of MIME boundary lines - typically a
 * multipart that is missing its closing <code>--&lt;boundary&gt;--</code>
 * line, so the part cannot be re-serialised for digest calculation
 * (see github #2318).
 * <p>
 * The exception message carries structural diagnostics only (the boundary,
 * the body part's Content-Type / Content-Disposition, the expected and found
 * boundary-line counts, and the number of bytes consumed) and is safe to log
 * or forward as-is. The last (non-empty) line read before the failure, which
 * may contain message content and is therefore potentially confidential, is
 * deliberately excluded from the message and is only available through
 * {@link #getLastLineRead()}.
 * </p>
 */
public class SMIMEBoundaryNotFoundException
    extends MessagingException
{
    private static final int LAST_LINE_LIMIT = 200;

    private final String boundary;
    private final String parentContentType;
    private final String parentContentDisposition;
    private final int expectedBoundaries;
    private final int foundBoundaries;
    private final long bytesConsumed;
    private final String lastLineRead;

    SMIMEBoundaryNotFoundException(
        String messageStem,
        String boundary,
        String parentContentType,
        String parentContentDisposition,
        int expectedBoundaries,
        int foundBoundaries,
        long bytesConsumed,
        String lastLineRead)
    {
        super(buildMessage(messageStem, boundary, parentContentType, parentContentDisposition,
            expectedBoundaries, foundBoundaries, bytesConsumed));

        this.boundary = boundary;
        this.parentContentType = parentContentType;
        this.parentContentDisposition = parentContentDisposition;
        this.expectedBoundaries = expectedBoundaries;
        this.foundBoundaries = foundBoundaries;
        this.bytesConsumed = bytesConsumed;
        this.lastLineRead = truncate(lastLineRead);
    }

    /**
     * Return the boundary line being searched for (with its leading
     * <code>--</code>).
     */
    public String getBoundary()
    {
        return boundary;
    }

    /**
     * Return the Content-Type of the body part whose raw content was being
     * scanned, or null if it could not be determined.
     */
    public String getParentContentType()
    {
        return parentContentType;
    }

    /**
     * Return the Content-Disposition of the body part whose raw content was
     * being scanned, or null if the header is absent or could not be read.
     */
    public String getParentContentDisposition()
    {
        return parentContentDisposition;
    }

    /**
     * Return the number of boundary lines the scan was looking for.
     */
    public int getExpectedBoundaries()
    {
        return expectedBoundaries;
    }

    /**
     * Return the number of boundary lines actually seen before end-of-stream.
     */
    public int getFoundBoundaries()
    {
        return foundBoundaries;
    }

    /**
     * Return the number of bytes consumed from the body part's raw input
     * stream before end-of-stream, for correlation with a dump of the
     * original message.
     */
    public long getBytesConsumed()
    {
        return bytesConsumed;
    }

    /**
     * Return the last non-empty line read before the scan hit end-of-stream,
     * truncated to 200 characters, or null if no non-empty line was seen.
     * <p>
     * <b>This value is part of the message body and may be confidential.</b>
     * It is excluded from {@link #getMessage()} so that stack traces are safe
     * to log by default; only forward it to sinks cleared for message
     * content.
     * </p>
     */
    public String getLastLineRead()
    {
        return lastLineRead;
    }

    private static String buildMessage(
        String messageStem,
        String boundary,
        String parentContentType,
        String parentContentDisposition,
        int expectedBoundaries,
        int foundBoundaries,
        long bytesConsumed)
    {
        StringBuilder sb = new StringBuilder(messageStem);

        sb.append(boundary);
        sb.append(" (");
        if (parentContentType != null)
        {
            sb.append("body part: Content-Type=\"").append(parentContentType).append('"');
            if (parentContentDisposition != null)
            {
                sb.append(", Content-Disposition=\"").append(parentContentDisposition).append('"');
            }
            sb.append("; ");
        }
        sb.append("expected ").append(expectedBoundaries).append(" boundary lines, found ").append(foundBoundaries);
        sb.append("; ").append(bytesConsumed).append(" bytes consumed)");

        return sb.toString();
    }

    private static String truncate(String line)
    {
        if (line == null || line.length() <= LAST_LINE_LIMIT)
        {
            return line;
        }
        return line.substring(0, LAST_LINE_LIMIT);
    }
}
