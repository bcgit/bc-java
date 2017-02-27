package org.bouncycastle.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Implements DigestAuth.
 */
public class HttpAuth
    implements ESTAuth
{
    private final String realm;
    private final String username;
    private final String password;
    private final SecureRandom nonceGenerator;

    public HttpAuth(String username, String password, SecureRandom nonceGenerator)
    {
        this(null, username, password, nonceGenerator);
    }

    public HttpAuth(String realm, String username, String password, SecureRandom nonceGenerator)
    {
        this.realm = realm;
        this.username = username;
        this.password = password;
        this.nonceGenerator = nonceGenerator;
    }

    public void applyAuth(final ESTRequestBuilder reqBldr)
    {
        reqBldr.withHijacker(new ESTHijacker()
        {
            public ESTResponse hijack(ESTRequest req, Source sock)
                throws IOException
            {
                ESTResponse res = new ESTResponse(req, sock);

                if (res.getStatusCode() == 401)
                {
                    String authHeader = Strings.toLowerCase(res.getHeader("WWW-Authenticate"));

                    if (authHeader.startsWith("digest"))
                    {
                        res = doDigestFunction(res);
                    }
                    else if (authHeader.startsWith("basic"))
                    {
                        res.close(); // Close off the last reqBldr.

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
                                throw new ESTException("Supplied realm '" + realm + "' does not match server realm '" + s.get("realm") + "'", null, 401, null);
                            }
                        }

                        //
                        // Prepare basic auth answer.
                        //
                        ESTRequestBuilder answer = new ESTRequestBuilder(req).withHijacker(null);

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

                        res = req.getClient().doRequest(answer.build());
                    }


                    return res;
                }
                return res;
            }
        });
    }

    protected ESTResponse doDigestFunction(ESTResponse res)
        throws IOException
    {
        res.close(); // Close off the last request.
        ESTRequest req = res.getOriginalRequest();
        Map<String, String> parts = HttpUtil.splitCSL("Digest", res.getHeader("WWW-Authenticate"));

        String uri = null;
        try
        {
            uri = req.getURL().toURI().getPath();
        }
        catch (URISyntaxException e)
        {
            throw new IOException("unable to process URL in request: " + e.getMessage());
        }

        String method = req.getMethod();
        String realm = parts.get("realm");
        String nonce = parts.get("nonce");
        String opaque = parts.get("opaque");
        String algorithm = parts.get("algorithm");
        String qop = parts.get("qop");
        List<String> qopMods = new ArrayList<String>(); // Preserve ordering.

        // Override the realm supplied by the server.

        if (this.realm != null)
        {
            realm = this.realm;
        }


        // If an algorithm is not specified, default to MD5.
        if (algorithm == null)
        {
            algorithm = "MD5";
        }

        algorithm = Strings.toUpperCase(algorithm);

        if (qop != null)
        {
            qop = Strings.toLowerCase(qop);
            String[] s = qop.split(",");
            for (String j : s)
            {
                String jt = j.trim();
                if (qopMods.contains(jt))
                {
                    continue;
                }
                qopMods.add(jt);
            }
        }
        else
        {
            qopMods.add("missing");
        }

        Digest dig = null;
        if (algorithm.equals("MD5") || algorithm.equals("MD5-SESS"))
        {
            dig = new MD5Digest();
        }

        byte[] ha1 = null;
        byte[] ha2 = null;

        DigestOutputStream dOut = new DigestOutputStream(dig);
        String crnonce = makeNonce(10); // TODO arbitrary?

        update(dOut, username);
        update(dOut, ":");
        update(dOut, realm);
        update(dOut, ":");
        update(dOut, password);

        dOut.close();
        
        ha1 = dOut.getDigest();

        if (algorithm.endsWith("-SESS"))
        {
            DigestOutputStream sessOut = new DigestOutputStream(dig);
            String cs = Hex.toHexString(ha1);

            update(sessOut, cs);
            update(sessOut, ":");
            update(sessOut, nonce);
            update(sessOut, ":");
            update(sessOut, crnonce);

            sessOut.close();

            ha1 = sessOut.getDigest();
        }

        String hashHa1 = Hex.toHexString(ha1);

        DigestOutputStream authOut = new DigestOutputStream(dig);

        if (qopMods.get(0).equals("auth-int"))
        {
            dig.reset();
            // Digest body
            DigestOutputStream reqOut = new DigestOutputStream(dig);

            req.writeData(reqOut);

            reqOut.close();

            byte[] b = reqOut.getDigest();

            dig.reset();

            update(authOut, method);
            update(authOut, ":");
            update(authOut, uri);
            update(authOut, ":");
            update(authOut, Hex.toHexString(b));
        }
        else if (qopMods.get(0).equals("auth"))
        {
            update(authOut, method);
            update(authOut, ":");
            update(authOut, uri);
        }

        authOut.close();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(bos);

        String hashHa2 = Hex.toHexString(authOut.getDigest());

        DigestOutputStream responseOut = new DigestOutputStream(dig);

        if (qopMods.contains("missing"))
        {
            update(responseOut, hashHa1);
            update(responseOut, ":");
            update(responseOut,nonce);
            update(responseOut, ":");
            update(responseOut, hashHa2);
        }
        else
        {
            update(responseOut, hashHa1);
            update(responseOut, ":");
            update(responseOut, nonce);
            update(responseOut, ":");
            update(responseOut, "00000001");
            update(responseOut, ":");
            update(responseOut, crnonce);
            update(responseOut, ":");

            if (qopMods.get(0).equals("auth-int"))
            {
                update(responseOut, "auth-int");
            }
            else
            {
                update(responseOut, "auth");
            }

            update(responseOut, ":");
            update(responseOut, hashHa2);
        }

        responseOut.close();

        String digest = Hex.toHexString(responseOut.getDigest());

        Map<String, String> hdr = new HashMap<String, String>();
        hdr.put("username", username);
        hdr.put("realm", realm);
        hdr.put("nonce", nonce);
        hdr.put("uri", uri);
        hdr.put("response", digest);
        if (qopMods.get(0).equals("auth-int"))
        {
            hdr.put("qop", "auth-int");
            hdr.put("nc", "00000001");
            hdr.put("cnonce", crnonce);
        }
        else if (qopMods.get(0).equals("auth"))
        {
            hdr.put("qop", "auth");
            hdr.put("nc", "00000001");
            hdr.put("cnonce", crnonce);
        }
        hdr.put("algorithm", algorithm);

        if (opaque == null || opaque.length() == 0)
        {
            hdr.put("opaque", makeNonce(20));
        }

        ESTRequestBuilder answer = new ESTRequestBuilder(req).withHijacker(null);
        answer.setHeader("Authorization", HttpUtil.mergeCSL("Digest", hdr));
        return req.getClient().doRequest(answer.build());
    }

    private void update(OutputStream dOut, String value)
        throws IOException
    {
        dOut.write(Strings.toUTF8ByteArray(value));
    }

    private String makeNonce(int len)
    {
        byte[] b = new byte[len];
        nonceGenerator.nextBytes(b);
        return Hex.toHexString(b);
    }

    //f0386ad8a5dfdc3d77914c5442c24233
}
