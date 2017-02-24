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
    HttpUtil.Headers headers = new HttpUtil.Headers();
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

    ESTRequest(String method, URL url, ESTClientRequestIdempotentInputSource writer, ESTHijacker hijacker, ESTSourceConnectionListener listener, HttpUtil.Headers headers)
    {
        this.method = method;
        this.url = url;
        this.writer = writer;
        this.hijacker = hijacker;
        this.listener = listener;
        this.headers = headers;
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
