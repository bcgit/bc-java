package org.bouncycastle.est;

import java.io.IOException;
import java.io.OutputStream;
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
    final byte[] data;
    final ESTHijacker hijacker;
    final ESTClient estClient;
    final ESTSourceConnectionListener listener;

    ESTRequest(
        String method,
        URL url,
        byte[] data,
        ESTHijacker hijacker,
        ESTSourceConnectionListener listener,
        HttpUtil.Headers headers,
        ESTClient estClient)
    {
        this.method = method;
        this.url = url;
        this.data = data;
        this.hijacker = hijacker;
        this.listener = listener;
        this.headers = headers;
        this.estClient = estClient;
    }

    public String getMethod()
    {
        return method;
    }

    public URL getURL()
    {
        return url;
    }

    public Map<String, String[]> getHeaders()
    {
        return (Map<String, String[]>)headers.clone();
    }

    public ESTHijacker getHijacker()
    {
        return hijacker;
    }

    public ESTClient getClient()
    {
        return estClient;
    }

    public ESTSourceConnectionListener getListener()
    {
        return listener;
    }

    public void writeData(OutputStream os)
        throws IOException
    {
        if (data != null)
        {
            os.write(data);
        }
    }
}
