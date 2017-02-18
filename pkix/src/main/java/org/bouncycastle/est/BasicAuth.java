package org.bouncycastle.est;

import java.io.IOException;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;

/**
 * BasicAuth implements http basic auth.
 */
public class BasicAuth
    implements ESTAuth
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


    public ESTRequest applyAuth(ESTRequest request)
    {

        //
        // Sets the header on the first request, does not wait for a 401.
        //
        if (realm != null && realm.length() > 0)
        {
            request.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        }
        if (username.contains(":"))
        {
            throw new IllegalArgumentException("User must not contain a ':'");
        }
        String userPass = username + ":" + password;
        request.setHeader("Authorization", "Basic " + Base64.toBase64String(userPass.getBytes()));

        return request;



//        return request.newWithHijacker(new ESTHijacker()
//        {
//            public ESTResponse hijack(ESTRequest req, Source sock)
//                throws ESTException, IOException
//            {
//                ESTResponse res = new ESTResponse(req, sock);
//                if (res.getStatusCode() == 401 && res.getHeader("WWW-Authenticate").startsWith("Basic"))
//                {
//                    res.close(); // Close off the last request.
//
//                    //
//                    // Check realm field from header.
//                    //
//                    Map<String, String> s = HttpUtil.splitCSL("Basic", res.getHeader("WWW-Authenticate"));
//
//                    //
//                    // If no realm supplied it will not check the server realm. TODO elaborate in documentation.
//                    //
//                    if (realm != null)
//                    {
//                        if (!realm.equals(s.get("realm")))
//                        {
//                            // Not equal then fail.
//                            throw new ESTException("Supplied realm '" + realm + "' does not match server realm '" + s.get("realm") + "'", 401, null, 0);
//                        }
//                    }
//
//                    //
//                    // Prepare basic auth answer.
//                    //
//                    ESTRequest answer = req.newWithHijacker(null);
//
//                    if (realm != null && realm.length() > 0)
//                    {
//                        answer.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
//                    }
//                    if (username.contains(":"))
//                    {
//                        throw new IllegalArgumentException("User must not contain a ':'");
//                    }
//                    String userPass = username + ":" + password;
//                    answer.setHeader("Authorization", "Basic " + Base64.toBase64String(userPass.getBytes()));
//
//                    res = req.getEstClient().doRequest(answer);
//                }
//                return res;
//            }
//        });
    }
}
