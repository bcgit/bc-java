package org.bouncycastle.est;

import java.net.URL;

/**
 * Builder for basic EST requests
 */
public class ESTRequestBuilder
{
    private final String method;
    private URL url;

    private HttpUtil.Headers headers;

    ESTClientRequestIdempotentInputSource writer;
    ESTHijacker hijacker;
    ESTSourceConnectionListener listener;
    ESTClient client;

    public ESTRequestBuilder(ESTRequest request)
    {

        this.method = request.method;
        this.url = request.url;
        this.listener = request.listener;
        this.writer = request.writer;
        this.hijacker = request.hijacker;
        this.headers = (HttpUtil.Headers)request.headers.clone();
        this.client = request.getClient();
    }

    public ESTRequestBuilder(String method, URL url)
    {
        this.method = method;
        this.url = url;
        this.headers = new HttpUtil.Headers();
    }

    public ESTRequestBuilder withClientRequestIdempotentInputSource(ESTClientRequestIdempotentInputSource writer)
    {
        this.writer = writer;

        return this;
    }

    public ESTRequestBuilder withConnectionListener(ESTSourceConnectionListener listener)
    {
        this.listener = listener;

        return this;
    }

    public ESTRequestBuilder withHijacker(ESTHijacker hijacker)
    {
        this.hijacker = hijacker;

        return this;
    }

    public ESTRequestBuilder withURL(URL url)
    {
        this.url = url;

        return this;
    }

    public ESTRequestBuilder addHeader(String key, String value)
    {
        headers.add(key, value);
        return this;
    }

    public ESTRequestBuilder setHeader(String key, String value)
    {
        headers.set(key, value);
        return this;
    }

    public ESTRequestBuilder withClient(ESTClient client)
    {
        this.client = client;
        return this;
    }

    public ESTRequest build()
    {
        return new ESTRequest(method, url, writer, hijacker, listener, headers, client);
    }
}
