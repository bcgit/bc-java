package org.bouncycastle.est;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements a basic http request.
 */
public class ESTRequest
{
    final String method;
    final URL url;
    final Map<String, List<String>> headers = new HashMap<String, List<String>>();
    final byte[] readAheadBuf = new byte[1024];
    final ESTClientRequestInputSource writer;
    final ESTHijacker hijacker;
    protected ESTClient estClient;
    final ESTSourceConnectionListener listener;


    public ESTRequest(String method, URL url, ESTClientRequestInputSource writer, ESTSourceConnectionListener listener)
    {
        this.method = method;
        this.url = url;
        this.writer = writer;
        this.hijacker = null;
        this.listener = listener;
    }

    public ESTRequest(String method, URL url, ESTSourceConnectionListener listener)
    {
        this.method = method;
        this.url = url;
        this.listener = listener;
        this.hijacker = null;
        this.writer = null;
    }


    public ESTRequest(String method, URL url, ESTClientRequestInputSource writer, ESTHijacker hijacker, ESTSourceConnectionListener listener)
    {
        this.method = method;
        this.url = url;
        this.writer = writer;
        this.hijacker = hijacker;
        this.listener = listener;
    }

    public ESTRequest(String method, URL url, ESTHijacker hijacker, ESTSourceConnectionListener listener)
    {
        this.method = method;
        this.url = url;
        this.hijacker = hijacker;
        this.listener = listener;
        this.writer = null;
    }

    public ESTRequest addHeader(String key, String value)
    {
        List<String> l = headers.get(key);
        if (l == null)
        {
            l = new ArrayList<String>();
            headers.put(key, l);
        }
        l.add(value);
        return this;
    }

    public ESTRequest copy()
    {
        return this.newWithHijacker(this.hijacker);
    }

    public ESTRequest setHeader(String key, String value)
    {
        headers.put(key, Collections.singletonList(value));
        return this;
    }


    public ESTRequest newWithHijacker(ESTHijacker estHttpHijacker)
    {
        ESTRequest req = new ESTRequest(this.method, this.url, this.writer, estHttpHijacker, listener);

        for (Map.Entry<String, List<String>> s : headers.entrySet())
        {
            req.headers.put(s.getKey(), s.getValue());
        }
        return req;
    }


    public ESTRequest newWithURL(URL url)
    {
        ESTRequest req = new ESTRequest(this.method, url, this.writer, hijacker, listener);

        for (Map.Entry<String, List<String>> s : headers.entrySet())
        {
            req.headers.put(s.getKey(), s.getValue());
        }
        return req;
    }


    public String getMethod()
    {
        return method;
    }

    public URL getUrl()
    {
        return url;
    }

    public Map<String, List<String>> getHeaders()
    {
        return headers;
    }

    public byte[] getReadAheadBuf()
    {
        return readAheadBuf;
    }

    public ESTClientRequestInputSource getWriter()
    {
        return writer;
    }

    public ESTHijacker getHijacker()
    {
        return hijacker;
    }

    public ESTClient getEstClient()
    {
        return estClient;
    }

    public void setEstClient(ESTClient estClient)
    {
        this.estClient = estClient;
    }

    public ESTSourceConnectionListener getListener()
    {
        return listener;
    }
}
