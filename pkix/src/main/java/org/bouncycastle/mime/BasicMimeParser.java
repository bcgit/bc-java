package org.bouncycastle.mime;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.mime.encoding.Base64InputStream;
import org.bouncycastle.mime.encoding.QuotedPrintableInputStream;

public class BasicMimeParser
    implements MimeParser
{
    private final InputStream src;
    private final MimeParserContext parserContext;
    private final String defaultContentTransferEncoding;
    private Headers headers;

    private boolean isMultipart = false;
    private final String boundary;

    public BasicMimeParser(
        InputStream src)
        throws IOException
    {
        this(null, new Headers(src, "7bit"), src);
    }

    public BasicMimeParser(
        MimeParserContext parserContext, InputStream src)
        throws IOException
    {
        this(parserContext, new Headers(src, parserContext.getDefaultContentTransferEncoding()), src);
    }

    public BasicMimeParser(
        Headers headers, InputStream content)
    {
        this(null, headers, content);
    }

    public BasicMimeParser(
        MimeParserContext parserContext, Headers headers, InputStream src)
    {
        if (headers.isMultipart())
        {
            isMultipart = true;
            boundary = headers.getBoundary();
        }
        else
        {
            boundary = null;
        }

        this.headers = headers;
        this.parserContext = parserContext;
        this.src = src;
        this.defaultContentTransferEncoding = (parserContext != null) ? parserContext.getDefaultContentTransferEncoding() : "7bit";
    }



    public void parse(MimeParserListener listener)
        throws IOException
    {
        MimeContext context = listener.createContext(parserContext, headers);

        String s;
        if (isMultipart)    // Signed
        {
            MimeMultipartContext mContext = (MimeMultipartContext)context;
            String startBoundary = "--" + boundary;
            boolean startFound = false;
            int partNo = 0;
            LineReader rd = new LineReader(src);
            while ((s = rd.readLine()) != null && !"--".equals(s))
            {
                if (startFound)
                {
                    InputStream inputStream = new BoundaryLimitedInputStream(src, boundary);
                    Headers headers = new Headers(inputStream, defaultContentTransferEncoding);

                    MimeContext partContext = mContext.createContext(partNo++);
                    inputStream = partContext.applyContext(headers, inputStream);

                    listener.object(parserContext, headers, processStream(headers, inputStream));

                    if (inputStream.read() >= 0)
                    {
                        throw new IOException("MIME object not fully processed");
                    }
                }
                else if (startBoundary.equals(s))
                {
                    startFound = true;
                    InputStream inputStream = new BoundaryLimitedInputStream(src, boundary);
                    Headers headers = new Headers(inputStream, defaultContentTransferEncoding);

                    MimeContext partContext = mContext.createContext(partNo++);
                    inputStream = partContext.applyContext(headers, inputStream);

                    listener.object(parserContext, headers, processStream(headers, inputStream));

                    if (inputStream.read() >= 0)
                    {
                        throw new IOException("MIME object not fully processed");
                    }
                }
            }
        }
        else
        {
            InputStream inputStream = context.applyContext(headers, src);

            listener.object(parserContext, headers, processStream(headers, inputStream));
        }
    }

    public boolean isMultipart()
    {
        return isMultipart;
    }

    private InputStream processStream(Headers headers, InputStream inputStream)
    {
        if (headers.getContentTransferEncoding().equals("base64"))
        {
            return new Base64InputStream(inputStream);
        }
        else if (headers.getContentTransferEncoding().equals("quoted-printable"))
        {
            return new QuotedPrintableInputStream(inputStream);
        }
        else
        {
            return inputStream;
        }
    }
}
