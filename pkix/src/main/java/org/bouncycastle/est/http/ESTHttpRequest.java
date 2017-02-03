package org.bouncycastle.est.http;

import java.net.URL;
import java.util.*;

/**
 * A basic http request.
 */
public class ESTHttpRequest
{
    final String method;
    final URL url;
    final Map<String, List<String>> headers = new HashMap<String, List<String>>();
    final byte[] readAheadBuf = new byte[1024];
    final ESTClientRequestInputSource writer;
    final ESTHttpHijacker hijacker;
    protected ESTHttpClient estHttpClient;


    public ESTHttpRequest(String method, URL url, ESTClientRequestInputSource writer)
    {
        this.method = method;
        this.url = url;
        this.writer = writer;
        this.hijacker = null;
    }

    public ESTHttpRequest(String method, URL url)
    {
        this.method = method;
        this.url = url;
        this.hijacker = null;
        this.writer = null;
    }


    public ESTHttpRequest(String method, URL url, ESTClientRequestInputSource writer, ESTHttpHijacker hijacker)
    {
        this.method = method;
        this.url = url;
        this.writer = writer;
        this.hijacker = hijacker;
    }

    public ESTHttpRequest(String method, URL url, ESTHttpHijacker hijacker)
    {
        this.method = method;
        this.url = url;
        this.hijacker = hijacker;
        this.writer = null;
    }

    public ESTHttpRequest addHeader(String key, String value)
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

    public ESTHttpRequest copy() {
        return this.newWithHijacker(this.hijacker);
    }

    public ESTHttpRequest setHeader(String key, String value)
    {
        headers.put(key, Collections.singletonList(value));
        return this;
    }


    protected ESTHttpRequest newWithHijacker(ESTHttpHijacker estHttpHijacker)
    {
        ESTHttpRequest req = new ESTHttpRequest(this.method, this.url, this.writer, estHttpHijacker);

        for (Map.Entry<String, List<String>> s : headers.entrySet())
        {
            req.headers.put(s.getKey(), s.getValue());
        }
        return req;
    }


    protected ESTHttpRequest newWithURL(URL url)
    {
        ESTHttpRequest req = new ESTHttpRequest(this.method, url, this.writer, hijacker);

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

    public ESTHttpHijacker getHijacker()
    {
        return hijacker;
    }

    public ESTHttpClient getEstHttpClient()
    {
        return estHttpClient;
    }

    public void setEstHttpClient(ESTHttpClient estHttpClient)
    {
        this.estHttpClient = estHttpClient;
    }
}
