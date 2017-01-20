package org.bouncycastle.est.http;

import java.net.Socket;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;

/**
 * BasicAuth implements http basic auth.
 */
public class BasicAuth
    implements ESTHttpAuth
{
    private final String realm;
    private final String username;
    private final String password;

    public BasicAuth(String realm, String username, String password)
    {
        this.realm = realm;
        this.username = username;
        this.password = password;
    }


    public ESTHttpRequest applyAuth(ESTHttpRequest request)
    {

        return request.newWithHijacker(new ESTHttpHijacker()
        {
            public ESTHttpResponse hijack(ESTHttpRequest req, Socket sock)
                throws Exception
            {
                ESTHttpResponse res = new ESTHttpResponse(req, sock);
                if (res.getStatusCode() == 401 && res.getHeader("WWW-Authenticate").startsWith("Basic"))
                {
                    res.close(); // Close off the last request.

                    //
                    // Check realm field from header.
                    //
                    Map<String, String> s = HttpUtil.splitCSL("Basic", res.getHeader("WWW-Authenticate"));

                    //
                    // If no realm supplied it will not check the server realm. TODO elaborate in documentation.
                    //
                    if (realm != null)
                    {
                        if (!realm.equals(s.get("realm")))
                        {
                            // Not equal then fail.
                            throw new ESTHttpException("Supplied realm '" + realm + "' does not match server realm '" + s.get("realm") + "'", 401, null, 0);
                        }
                    }

                    //
                    // Prepare basic auth answer.
                    //
                    ESTHttpRequest answer = req.newWithHijacker(null);

                    if (realm != null && realm.length() > 0)
                    {
                        answer.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
                    }
                    if (username.contains(":"))
                    {
                        throw new IllegalArgumentException("User must not contain a ':'");
                    }
                    String userPass = username + ":" + password;
                    answer.setHeader("Authorization", "Basic " + Base64.toBase64String(userPass.getBytes()));

                    res = req.getEstHttpClient().doRequest(answer);
                }
                return res;
            }
        });
    }
}
