package org.bouncycastle.est;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Provides stock implementations for basic auth and digest auth.
 */
public class HttpAuth
    implements ESTAuth
{
    private static final DigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

    private final String realm;
    private final String username;
    private final char[] password;
    private final SecureRandom nonceGenerator;
    private final DigestCalculatorProvider digestCalculatorProvider;

    private static final Set<String> validParts;

    static
    {
        HashSet<String> s = new HashSet<String>();
        s.add("realm");
        s.add("nonce");
        s.add("opaque");
        s.add("algorithm");
        s.add("qop");
        validParts = Collections.unmodifiableSet(s);
    }

    /**
     * Base constructor for basic auth.
     *
     * @param username user id.
     * @param password user's password.
     */
    public HttpAuth(String username, char[] password)
    {
        this(null, username, password, null, null);
    }

    /**
     * Constructor for basic auth with a specified realm.
     *
     * @param realm    expected server realm.
     * @param username user id.
     * @param password user's password.
     */
    public HttpAuth(String realm, String username, char[] password)
    {
        this(realm, username, password, null, null);
    }

    /**
     * Base constructor for digest auth. The realm will be set by
     *
     * @param username                 user id.
     * @param password                 user's password.
     * @param nonceGenerator           random source for generating nonces.
     * @param digestCalculatorProvider provider for digest calculators needed for calculating hashes.
     */
    public HttpAuth(String username, char[] password, SecureRandom nonceGenerator, DigestCalculatorProvider digestCalculatorProvider)
    {
        this(null, username, password, nonceGenerator, digestCalculatorProvider);
    }

    /**
     * Constructor for digest auth with a specified realm.
     *
     * @param realm                    expected server realm.
     * @param username                 user id.
     * @param password                 user's password.
     * @param nonceGenerator           random source for generating nonces.
     * @param digestCalculatorProvider provider for digest calculators needed for calculating hashes.
     */
    public HttpAuth(String realm, String username, char[] password, SecureRandom nonceGenerator, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.realm = realm;
        this.username = username;
        this.password = password;
        this.nonceGenerator = nonceGenerator;
        this.digestCalculatorProvider = digestCalculatorProvider;
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
                    String authHeader = res.getHeader("WWW-Authenticate");
                    if (authHeader == null)
                    {
                        throw new ESTException("Status of 401 but no WWW-Authenticate header");
                    }

                    authHeader = Strings.toLowerCase(authHeader);

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
                        //userPass = username + ":" + password;
                        char[]  userPass = new char[username.length() + 1 + password.length];
                        System.arraycopy(username.toCharArray(), 0, userPass, 0, username.length());
                        userPass[username.length()] = ':';
                        System.arraycopy(password, 0, userPass, username.length() + 1, password.length);

                        answer.setHeader("Authorization", "Basic " + Base64.toBase64String(Strings.toByteArray(userPass)));

                        res = req.getClient().doRequest(answer.build());

                        Arrays.fill(userPass, (char)0);
                    }
                    else
                    {
                        throw new ESTException("Unknown auth mode: " + authHeader);
                    }


                    return res;
                }
                return res;
            }
        });
    }

    private ESTResponse doDigestFunction(ESTResponse res)
        throws IOException
    {
        res.close(); // Close off the last request.
        ESTRequest req = res.getOriginalRequest();


        Map<String, String> parts = null;
        try
        {
            parts = HttpUtil.splitCSL("Digest", res.getHeader("WWW-Authenticate"));
        }
        catch (Throwable t)
        {
            throw new ESTException(
                "Parsing WWW-Authentication header: " + t.getMessage(),
                t,
                res.getStatusCode(),
                new ByteArrayInputStream(res.getHeader("WWW-Authenticate").getBytes()));
        }


        String uri = null;
        try
        {
            uri = req.getURL().toURI().getPath();
        }
        catch (Exception e)
        {
            throw new IOException("unable to process URL in request: " + e.getMessage());
        }

        for (Iterator it = parts.keySet().iterator(); it.hasNext();)
        {
            Object k = it.next();
            if (!validParts.contains(k))
            {
                throw new ESTException("Unrecognised entry in WWW-Authenticate header: '" + k + "'");
            }
        }

        String method = req.getMethod();
        String realm = parts.get("realm");
        String nonce = parts.get("nonce");
        String opaque = parts.get("opaque");
        String algorithm = parts.get("algorithm");
        String qop = parts.get("qop");


        List<String> qopMods = new ArrayList<String>(); // Preserve ordering.

        if (this.realm != null)
        {
            if (!this.realm.equals(realm))
            {
                // Not equal then fail.
                throw new ESTException("Supplied realm '" + this.realm + "' does not match server realm '" + realm + "'", null, 401, null);
            }
        }

        // If an algorithm is not specified, default to MD5.
        if (algorithm == null)
        {
            algorithm = "MD5";
        }

        if (algorithm.length() == 0)
        {
            throw new ESTException("WWW-Authenticate no algorithm defined.");
        }

        algorithm = Strings.toUpperCase(algorithm);

        if (qop != null)
        {
            if (qop.length() == 0)
            {
                throw new ESTException("QoP value is empty.");
            }

            qop = Strings.toLowerCase(qop);
            String[] s = qop.split(",");
            for (int j = 0; j != s.length; j++)
            {
                if (!s[j].equals("auth") && !s[j].equals("auth-int"))
                {
                    throw new ESTException("QoP value unknown: '" + j + "'");
                }

                String jt = s[j].trim();
                if (qopMods.contains(jt))
                {
                    continue;
                }
                qopMods.add(jt);
            }
        }
        else
        {
            throw new ESTException("Qop is not defined in WWW-Authenticate header.");
        }


        AlgorithmIdentifier digestAlg = lookupDigest(algorithm);
        if (digestAlg == null || digestAlg.getAlgorithm() == null)
        {
            throw new IOException("auth digest algorithm unknown: " + algorithm);
        }

        DigestCalculator dCalc = getDigestCalculator(algorithm, digestAlg);
        OutputStream dOut = dCalc.getOutputStream();

        String crnonce = makeNonce(10); // TODO arbitrary?

        update(dOut, username);
        update(dOut, ":");
        update(dOut, realm);
        update(dOut, ":");
        update(dOut, password);

        dOut.close();

        byte[] ha1 = dCalc.getDigest();

        if (algorithm.endsWith("-SESS"))
        {
            DigestCalculator sessCalc = getDigestCalculator(algorithm, digestAlg);
            OutputStream sessOut = sessCalc.getOutputStream();

            String cs = Hex.toHexString(ha1);

            update(sessOut, cs);
            update(sessOut, ":");
            update(sessOut, nonce);
            update(sessOut, ":");
            update(sessOut, crnonce);

            sessOut.close();

            ha1 = sessCalc.getDigest();
        }

        String hashHa1 = Hex.toHexString(ha1);

        DigestCalculator authCalc = getDigestCalculator(algorithm, digestAlg);
        OutputStream authOut = authCalc.getOutputStream();

        if (qopMods.get(0).equals("auth-int"))
        {
            DigestCalculator reqCalc = getDigestCalculator(algorithm, digestAlg);
            OutputStream reqOut = reqCalc.getOutputStream();

            req.writeData(reqOut);

            reqOut.close();

            byte[] b = reqCalc.getDigest();

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

        String hashHa2 = Hex.toHexString(authCalc.getDigest());

        DigestCalculator responseCalc = getDigestCalculator(algorithm, digestAlg);
        OutputStream responseOut = responseCalc.getOutputStream();

        if (qopMods.contains("missing"))
        {
            update(responseOut, hashHa1);
            update(responseOut, ":");
            update(responseOut, nonce);
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

        String digest = Hex.toHexString(responseCalc.getDigest());

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

    private DigestCalculator getDigestCalculator(String algorithm, AlgorithmIdentifier digestAlg)
        throws IOException
    {
        DigestCalculator dCalc;
        try
        {
            dCalc = digestCalculatorProvider.get(digestAlg);
        }
        catch (OperatorCreationException e)
        {
            throw new IOException("cannot create digest calculator for " + algorithm + ": " + e.getMessage());
        }
        return dCalc;
    }

    private AlgorithmIdentifier lookupDigest(String algorithm)
    {
        if (algorithm.endsWith("-SESS"))
        {
            algorithm = algorithm.substring(0, algorithm.length() - "-SESS".length());
        }

        if (algorithm.equals("SHA-512-256"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256, DERNull.INSTANCE);
        }

        return digestAlgorithmIdentifierFinder.find(algorithm);
    }

    private void update(OutputStream dOut, char[] value)
        throws IOException
    {
        dOut.write(Strings.toUTF8ByteArray(value));
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
}
