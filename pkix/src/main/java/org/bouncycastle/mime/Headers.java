package org.bouncycastle.mime;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.util.Strings;

public class Headers
    implements Iterable<String>
{
    private final Map<String, List<KV>> headers = new TreeMap<String, List<KV>>(String.CASE_INSENSITIVE_ORDER);
    private final List<String> headersAsPresented;
    private final String contentTransferEncoding;

    private String boundary;
    private boolean multipart;
    private String contentType;

    private static List<String> parseHeaders(InputStream src)
        throws IOException
    {
        String s;
        List<String> headerLines = new ArrayList<String>();

        while ((s = MimeUtils.readLine(src)) != null)
        {
            if (s.length() == 0)
            {
                break;
            }
            headerLines.add(s);
        }

        return headerLines;
    }

    public Headers(InputStream source, String defaultContentTransferEncoding)
        throws IOException
    {
        this(parseHeaders(source), defaultContentTransferEncoding);
    }

    public Headers(List<String> headerLines, String defaultContentTransferEncoding)
    {
        this.headersAsPresented = headerLines;

        String header = "";
        for (String line : headerLines)
        {
            if (line.startsWith(" ") || line.startsWith("\t"))
            {
                header = header + line.trim();
            }
            else
            {
                if (header.length() != 0)
                {
                    this.put(header.substring(0, header.indexOf(':')).trim(), header.substring(header.indexOf(':') + 1).trim());
                }
                header = line;
            }
        }

        // pick up last header line
        if (header.trim().length() != 0)
        {
            this.put(header.substring(0, header.indexOf(':')).trim(), header.substring(header.indexOf(':') + 1).trim());
        }

        contentType = (this.getValues("Content-Type") == null) ? "text/plain" : this.getValues("Content-Type")[0];
        contentTransferEncoding = this.getValues("Content-Transfer-Encoding") == null ? defaultContentTransferEncoding : this.getValues("Content-Transfer-Encoding")[0];

        if (contentType.contains("multipart"))
        {
            multipart = true;
            String bound = contentType.substring(contentType.indexOf("boundary=\"") + 10);
            boundary = bound.substring(0, bound.indexOf('"'));
        }
        else
        {
            boundary = null;
            multipart = false;
        }
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
            List<KV> list = headers.get(field);
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
            List<KV> kvList = headers.get(header);
            if (kvList == null)
            {
                return null;
            }
            String[] out = new String[kvList.size()];

            for (int t = 0; t < kvList.size(); t++)
            {
                out[t] = kvList.get(t).value;
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

    @Override
    public Iterator<String> iterator()
    {
        return headers.keySet().iterator();
    }

    public void dumpHeaders(OutputStream outputStream)
        throws IOException
    {
        for (String line : headersAsPresented)
        {
            outputStream.write(Strings.toUTF8ByteArray(line));
            outputStream.write('\r');
            outputStream.write('\n');
        }
    }

    private class KV
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

        /**
         * Canonical form.
         *
         * @return The header with properly terminated lineendings and so on.
         */
        public String canonicalForm()
        {
            StringBuffer stringBuffer = new StringBuffer();
            for (String s : value.split("\n"))
            {
                stringBuffer.append(s);
                if (s.endsWith("\r"))
                {
                    stringBuffer.append("\n");
                }
                else
                {
                    stringBuffer.append("\r\n");
                }
            }
            return key + ":" + stringBuffer.toString();
        }
    }
}
