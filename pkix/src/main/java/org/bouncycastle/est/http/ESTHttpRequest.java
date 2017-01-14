package org.bouncycastle.est.http;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;

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

    boolean digestAuth = false;

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

    public ESTHttpRequest withBasicAuth(String realm, String user, String password)
    {
        if (realm != null && realm.length() > 0)
        {
            headers.put("WWW-Authenticate", Collections.singletonList("Basic realm=\"" + realm + "\""));
        }
        if (user.contains(":"))
        {
            throw new IllegalArgumentException("User must not contain a ':'");
        }
        String userPass = user + ":" + password;
        headers.put("Authorization", Collections.singletonList("Basic " + Base64.toBase64String(userPass.getBytes())));
        return this;
    }



}
