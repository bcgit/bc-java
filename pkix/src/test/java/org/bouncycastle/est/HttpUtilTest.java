package org.bouncycastle.est;

import java.util.Map;

import junit.framework.TestCase;

/**
 * Regression coverage for the package-private {@link HttpUtil#splitCSL} parser
 * (the {@code PartLexer}) that decodes the comma-separated {@code key="value"}
 * pairs of an HTTP {@code WWW-Authenticate} challenge. In particular it pins the
 * fix for an alpha label running to the end of the input: {@code consumeAlpha}
 * used to read one character past the end and throw an unchecked
 * {@link StringIndexOutOfBoundsException} instead of the intended
 * {@link IllegalArgumentException}.
 */
public class HttpUtilTest
    extends TestCase
{
    public void testSplitCSL()
    {
        Map<String, String> m = HttpUtil.splitCSL("Digest ",
            "Digest realm=\"testrealm\", nonce=\"abc123\", qop=\"auth\"");
        assertEquals(3, m.size());
        assertEquals("testrealm", m.get("realm"));
        assertEquals("abc123", m.get("nonce"));
        assertEquals("auth", m.get("qop"));

        // the skip prefix is only stripped when actually present
        Map<String, String> noPrefix = HttpUtil.splitCSL("Basic ", "realm=\"r\"");
        assertEquals("r", noPrefix.get("realm"));

        // single entry exercises the no-trailing-comma break
        assertEquals("v", HttpUtil.splitCSL("", "k=\"v\"").get("k"));

        // a trailing comma is tolerated: the comma is consumed and the loop
        // then exits because p has reached the (trimmed) end of input
        assertEquals("v", HttpUtil.splitCSL("", "k=\"v\",").get("k"));
    }

    public void testSplitCSLMalformed()
    {
        // missing '=' after the label
        checkRejected("realm \"r\"");
        // value not started with a quote
        checkRejected("realm=r");
        // empty / non-alpha label
        checkRejected("=\"r\"");
        // alpha label runs to end-of-input with no following '=': consumeAlpha
        // read one char past the end -> StringIndexOutOfBoundsException before
        // the fix, now a clean IllegalArgumentException
        checkRejected("realm");
    }

    private void checkRejected(String src)
    {
        try
        {
            HttpUtil.splitCSL("", src);
            fail("expected IllegalArgumentException for: " + src);
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }
}
