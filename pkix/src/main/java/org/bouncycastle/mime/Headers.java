package org.bouncycastle.mime;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Iterable;
import org.bouncycastle.util.Strings;

public class Headers
    implements Iterable<String>
{
    private final Map<String, List> headers = new TreeMap<String, List>(String.CASE_INSENSITIVE_ORDER);
    private final List<String> headersAsPresented;
    private String contentTransferEncoding;

    private String boundary;
    private boolean multipart;
    private String contentType;
    private Map<String, String> contentTypeParameters;

    private static List<String> parseHeaders(InputStream src)
        throws IOException
    {
        String s;
        List<String> headerLines = new ArrayList<String>();
        LineReader   rd = new LineReader(src);

        while ((s = rd.readLine()) != null)
        {
            if (s.length() == 0)
            {
                break;
            }
            headerLines.add(s);
        }

        return headerLines;
    }

    /**
     * Create specifying content type header value and default content transfer encoding.
     *
     * @param contentType                    The content type value
     * @param defaultContentTransferEncoding default content transfer encoding.
     */
    public Headers(String contentType, String defaultContentTransferEncoding)
    {
        headersAsPresented = new ArrayList<String>();
        headersAsPresented.add("Content-Type: " + contentType);

        initUnchecked(defaultContentTransferEncoding);
    }

    public Headers(InputStream source, String defaultContentTransferEncoding)
        throws IOException
    {
        this.headersAsPresented = parseHeaders(source);

        init(defaultContentTransferEncoding);
    }

    public Headers(List<String> headerLines, String defaultContentTransferEncoding)
    {
        this.headersAsPresented = headerLines;

        initUnchecked(defaultContentTransferEncoding);
    }

    /**
     * These two constructors cannot add a checked exception to their signatures, so malformed input
     * reaches their callers as an IllegalArgumentException carrying the same message and the
     * IOException as its cause. The stream constructor above, which the S/MIME parsers use, reports
     * it as the IOException it declares.
     */
    private void initUnchecked(String defaultContentTransferEncoding)
    {
        try
        {
            init(defaultContentTransferEncoding);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalArgumentException(e.getMessage(), e);
        }
    }

    /**
     * Single copy of the header split and Content-Type interpretation for all three constructors -
     * it was duplicated between two of them, and they had drifted: the boundary handling below was
     * corrected for an unquoted value in one copy and not the other.
     */
    private void init(String defaultContentTransferEncoding)
        throws IOException
    {
        String header = "";
        for (Iterator it = headersAsPresented.iterator(); it.hasNext();)
        {
            String line = (String)it.next();
            if (line.startsWith(" ") || line.startsWith("\t"))
            {
                header = header + line.trim();
            }
            else
            {
                if (header.length() != 0)
                {
                    putHeader(header);
                }
                header = line;
            }
        }

        // pick up last header line
        if (header.trim().length() != 0)
        {
            putHeader(header);
        }

        String contentTypeHeader = (this.getValues("Content-Type") == null) ? "text/plain" : this.getValues("Content-Type")[0];

        int parameterIndex = contentTypeHeader.indexOf(';');
        if (parameterIndex < 0)
        {
            contentType = contentTypeHeader;
            contentTypeParameters = Collections.EMPTY_MAP;
        }
        else
        {
            contentType = contentTypeHeader.substring(0, parameterIndex);
            contentTypeParameters = createContentTypeParameters(contentTypeHeader.substring(parameterIndex + 1).trim());
        }

        contentTransferEncoding = this.getValues("Content-Transfer-Encoding") == null ? defaultContentTransferEncoding : this.getValues("Content-Transfer-Encoding")[0];

        if (contentType.indexOf("multipart") >= 0)    // JVM compatibility
        {
            multipart = true;
            boundary = parseBoundary((String)contentTypeParameters.get("boundary"));
        }
        else
        {
            boundary = null;
            multipart = false;
        }
    }

    private void putHeader(String header)
        throws IOException
    {
        int colonIndex = header.indexOf(':');
        if (colonIndex < 0)
        {
            // substring(0, -1) otherwise, which is not a diagnosis of anything
            throw new IOException("header line has no ':' delimiter");
        }

        this.put(header.substring(0, colonIndex).trim(), header.substring(colonIndex + 1).trim());
    }

    private static String parseBoundary(String bound)
        throws IOException
    {
        if (bound == null)
        {
            throw new IOException("no boundary parameter for multipart content type");
        }

        // RFC 2046 sec. 5.1.1 allows the boundary either as a quoted-string or bare, and the
        // length test keeps a lone quote character from being read as both delimiters
        String boundary = bound.length() > 1 && bound.startsWith("\"") && bound.endsWith("\"")
            ? bound.substring(1, bound.length() - 1)
            : bound;

        if (boundary.length() == 0)
        {
            throw new IOException("empty boundary parameter for multipart content type");
        }

        return boundary;
    }

    /**
     * Return the a Map of the ContentType attributes and their values.
     *
     * @return a Map of ContentType parameters - empty if none present.
     */
    public Map<String, String> getContentTypeAttributes()
    {
        return contentTypeParameters;
    }

    /**
     * Return the a list of the ContentType parameters.
     *
     * @return a list of ContentType parameters - empty if none present.
     */
    private Map<String, String> createContentTypeParameters(String contentTypeParameters)
        throws IOException
    {
        String[] parameterSplit = contentTypeParameters.split(";");
        Map<String, String> rv = new LinkedHashMap<String, String>();

        for (int i = 0; i != parameterSplit.length; i++)
        {
            String parameter = parameterSplit[i];

            int eqIndex = parameter.indexOf('=');
            if (eqIndex < 0)
            {
                throw new IOException("malformed Content-Type header");
            }

            rv.put(parameter.substring(0, eqIndex).trim(), parameter.substring(eqIndex + 1).trim());
        }

        return Collections.unmodifiableMap(rv);
    }

    public boolean isMultipart()
    {
        return multipart;
    }

    public String getBoundary()
    {
        return boundary;
    }

    public String getContentType()
    {
        return contentType;
    }

    public String getContentTransferEncoding()
    {
        return contentTransferEncoding;
    }

    private void put(String field, String value)
    {
        synchronized (this)
        {
            KV kv = new KV(field, value);
            List<KV> list = (List<KV>)headers.get(field);
            if (list == null)
            {
                list = new ArrayList<KV>();
                headers.put(field, list);
            }
            list.add(kv);
        }
    }

    public Iterator<String> getNames()
    {
        return headers.keySet().iterator();
    }

    public String[] getValues(String header)
    {

        synchronized (this)
        {
            List<KV> kvList = (List<KV>)headers.get(header);
            if (kvList == null)
            {
                return null;
            }
            String[] out = new String[kvList.size()];

            for (int t = 0; t < kvList.size(); t++)
            {
                out[t] = ((KV)kvList.get(t)).value;
            }

            return out;
        }
    }

    public boolean isEmpty()
    {
        synchronized (this)
        {
            return headers.isEmpty();
        }
    }

    public boolean containsKey(String s)
    {
        return headers.containsKey(s);
    }

    public Iterator<String> iterator()
    {
        return headers.keySet().iterator();
    }

    public void dumpHeaders(OutputStream outputStream)
        throws IOException
    {
        for (Iterator it = headersAsPresented.iterator(); it.hasNext();)
        {
            outputStream.write(Strings.toUTF8ByteArray(it.next().toString()));
            outputStream.write('\r');
            outputStream.write('\n');
        }
    }

    private static class KV
    {
        public final String key;
        public final String value;

        public KV(String key, String value)
        {
            this.key = key;
            this.value = value;
        }

        public KV(KV kv)
        {
            this.key = kv.key;
            this.value = kv.value;
        }
    }
}
