package org.bouncycastle.est;

import java.net.URL;
import java.util.Map;

/**
 * Implements a basic http request.
 */
public class ESTRequest
{
    final String method;
    final URL url;
    final HttpUtil.Headers headers = new HttpUtil.Headers();
    final byte[] readAheadBuf = new byte[1024];
    final ESTClientRequestIdempotentInputSource writer;
    final ESTHijacker hijacker;
    protected ESTClient estClient;
    final ESTSourceConnectionListener listener;


    public ESTRequest(String method, URL url, ESTClientRequestIdempotentInputSource writer, ESTSourceConnectionListener listener)
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


    public ESTRequest(String method, URL url, ESTClientRequestIdempotentInputSource writer, ESTHijacker hijacker, ESTSourceConnectionListener listener)
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
        headers.add(key, value);
        return this;
    }

    public ESTRequest copy()
    {
        return this.newWithHijacker(this.hijacker);
    }

    public ESTRequest setHeader(String key, String value)
    {
        headers.set(key, value);
        return this;
    }


    public ESTRequest newWithHijacker(ESTHijacker estHttpHijacker)
    {
        ESTRequest req = new ESTRequest(this.method, this.url, this.writer, estHttpHijacker, listener);

        for (Map.Entry<String, String[]> s : headers.entrySet())
        {
            req.headers.put(s.getKey(), s.getValue());
        }
        return req;
    }


    public ESTRequest newWithURL(URL url)
    {
        ESTRequest req = new ESTRequest(this.method, url, this.writer, hijacker, listener);

        for (Map.Entry<String, String[]> s : headers.entrySet())
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

    public HttpUtil.Headers getHeaders()
    {
        return headers;
    }

    public byte[] getReadAheadBuf()
    {
        return readAheadBuf;
    }

    public ESTClientRequestIdempotentInputSource getWriter()
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
