package org.bouncycastle.est.http;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public ESTHttpRequest(String method, URL url, ESTClientRequestInputSource writer)
    {
        this.method = method;
        this.url = url;
        this.writer = writer;
    }

    public ESTHttpRequest(String method, URL url)
    {
        this.method = method;
        this.url = url;
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

}
