package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Base class for stream generators for definite-length structures. Unlike the
 * {@link BERGenerator BER generators}, which stream indefinite-length
 * encodings, these write a definite-length header up front from a
 * caller-supplied body length and so can stream DL (and, with suitably
 * canonical contents, DER) encodings of structures too large to hold in
 * memory — body lengths are {@code long}, so content larger than a Java array
 * can carry is supported.
 *
 * <p>The body length passed to a generator is a commitment: the matching
 * number of content octets must subsequently be written. Subclasses verify
 * this on {@link DLSequenceGenerator#close() close()} and fail with an
 * {@link IOException} on a mismatch, since a wrongly-sized body silently
 * corrupts every enclosing length.</p>
 */
public abstract class DLGenerator
    extends ASN1Generator
{
    private boolean _tagged = false;
    private boolean _isExplicit;
    private int _tagNo;

    protected DLGenerator(OutputStream out)
    {
        super(out);
    }

    protected DLGenerator(OutputStream out, int tagNo, boolean isExplicit)
    {
        super(out);

        _tagged = true;
        _isExplicit = isExplicit;
        _tagNo = tagNo;
    }

    public OutputStream getRawOutputStream()
    {
        return _out;
    }

    /**
     * Return the number of octets in the definite-length encoding of
     * {@code bodyLength} (the length octets only, excluding the identifier).
     *
     * @param bodyLength number of content octets ({@code >= 0})
     * @return 1 for the short form, 1 + number of length octets for the long form
     */
    public static int getLengthOctetCount(long bodyLength)
    {
        if (bodyLength < 0)
        {
            throw new IllegalArgumentException("bodyLength cannot be negative");
        }
        if (bodyLength < 0x80)
        {
            return 1;
        }
        int count = 1;
        long l = bodyLength;
        while (l != 0)
        {
            count++;
            l >>>= 8;
        }
        return count;
    }

    /**
     * Return the total encoded length of a TLV with a single identifier octet
     * (i.e. a tag number below 31) and {@code bodyLength} content octets.
     *
     * @param bodyLength number of content octets ({@code >= 0})
     */
    public static long getDLEncodingLength(long bodyLength)
    {
        return 1 + getLengthOctetCount(bodyLength) + bodyLength;
    }

    static void writeLength(OutputStream out, long bodyLength)
        throws IOException
    {
        if (bodyLength < 0)
        {
            throw new IllegalArgumentException("bodyLength cannot be negative");
        }
        if (bodyLength < 0x80)
        {
            out.write((int)bodyLength);
            return;
        }
        int octets = 0;
        long l = bodyLength;
        while (l != 0)
        {
            octets++;
            l >>>= 8;
        }
        out.write(0x80 | octets);
        for (int i = (octets - 1) * 8; i >= 0; i -= 8)
        {
            out.write((int)(bodyLength >>> i));
        }
    }

    private void writeHdr(int tag, long bodyLength)
        throws IOException
    {
        _out.write(tag);
        writeLength(_out, bodyLength);
    }

    private void writeHdr(int flags, int tagNo, long bodyLength)
        throws IOException
    {
        ASN1OutputStream.writeIdentifier(_out, flags, tagNo);
        writeLength(_out, bodyLength);
    }

    /**
     * Write the definite-length header(s) for this generator's structure:
     * the base tag with {@code bodyLength}, preceded (for an explicit tag) by
     * a context-specific wrapper whose length covers the complete base TLV.
     * Tag numbers of 31 and above are supported for the context-specific
     * wrapper of an implicitly tagged structure, but not for an explicit one
     * (the wrapper length arithmetic assumes a single identifier octet).
     */
    protected void writeDLHeader(int tag, long bodyLength)
        throws IOException
    {
        if (!_tagged)
        {
            writeHdr(tag, bodyLength);
        }
        else if (_isExplicit)
        {
            /*
             * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
             * and the contents octets shall be the complete base encoding.
             */
            if (_tagNo > 30)
            {
                throw new IOException("explicit tag numbers > 30 not supported by DL generators");
            }
            writeHdr(BERTags.CONTEXT_SPECIFIC | BERTags.CONSTRUCTED, _tagNo, getDLEncodingLength(bodyLength));
            writeHdr(tag, bodyLength);
        }
        else
        {
            /*
             * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
             * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
             * shall be [..] the contents octets of the base encoding.
             */
            writeHdr(inheritConstructedFlag(BERTags.CONTEXT_SPECIFIC, tag), _tagNo, bodyLength);
        }
    }

    /**
     * An OutputStream wrapper that enforces an exact number of content octets:
     * writing past the limit fails immediately, and {@link #finish()} fails if
     * fewer octets than promised were written. Used by the DL generators to
     * guarantee the pre-committed definite lengths stay truthful.
     */
    static class ExactLengthOutputStream
        extends OutputStream
    {
        private final OutputStream _target;
        private final long _limit;
        private long _written = 0;

        ExactLengthOutputStream(OutputStream target, long limit)
        {
            _target = target;
            _limit = limit;
        }

        public void write(int b)
            throws IOException
        {
            checkSpace(1);
            _target.write(b);
            _written++;
        }

        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            checkSpace(len);
            _target.write(buf, off, len);
            _written += len;
        }

        public void flush()
            throws IOException
        {
            _target.flush();
        }

        private void checkSpace(int len)
            throws IOException
        {
            if (_written + len > _limit)
            {
                throw new IOException("attempt to write more than the declared " + _limit + " octets");
            }
        }

        long getWritten()
        {
            return _written;
        }

        /**
         * Check the promised octet count has been written. Deliberately not
         * close(): the target stream stays open and untouched.
         */
        void finish()
            throws IOException
        {
            if (_written != _limit)
            {
                throw new IOException("fewer octets written (" + _written + ") than the declared " + _limit);
            }
        }
    }
}
