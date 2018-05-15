package org.bouncycastle.est.test;

import java.io.IOException;
import java.util.HashSet;

import junit.framework.TestCase;
import org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer;

public class HostNameAuthorizerMatchTest
    extends TestCase
{
    public void testWildcardMatcher()
        throws Exception
    {

        Object[][] v = new Object[][]{
            //   {"Too wide a match", "foo.com","*.com",false}, // too wide a match
            {"Exact", "a.foo.com", "a.foo.com", true},
            {"Left most", "abacus.foo.com", "*s.foo.com", true}, // Match the left most.
            {"Invalid 1","localhost.cisco.com","localhost.*.com",true},
            {"Invalid 2", "localhost.cisco.com", "localhost.cisco.*", false},
            {"Invalid 3 - subdomain","localhost.cisco.com","*.com",false},
            {"Invalid 4", "localhost.cisco.com", "*.localhost.cisco.com", false},
            {"Invalid 5", "localhost.cisco.com", "*", false},
            {"Invalid 6", "localhost.cisco.com", "localhost*.cisco.com", true},
            {"Invalid 7", "localhost.cisco.com", "*localhost.cisco.com", false},
            {"Invalid 8", "localhost.cisco.com", "local*host.cisco.com", true},
            {"Invalid 9", "localhost.cisco.com", "localhost.c*.com", true},
            {"Invalid 10", "localhost.cisco.com", "localhost.*o.com", true},
            {"Invalid 11", "localhost.cisco.com", "localhost.c*o.com", true},
            {"Invalid 12", "localhost.cisco.com", "*..com", false},
            {"Invalid 13", "foo.example.com","*.example.com",true},
            {"Invalid 14", "bar.foo.example.com", "*.example.com", false},
            {"Invalid 15", "example.com", "*.example.com", false},
            {"Invalid 16", "foobaz.example.com","b*z.example.com",false},
            {"Invalid 17", "foobaz.example.com","ob*z.example.com",false},
            { "Valid", "foobaz.example.com","foob*z.example.com",true}
        };

        for (Object[] j : v)
        {
            assertEquals(j[0].toString(), j[3], JsseDefaultHostnameAuthorizer.isValidNameMatch((String)j[1], (String)j[2], null));
        }
    }

    public void testWildcardPublicSuffix()
        throws Exception
    {

        Object[][] v = new Object[][]{

            {"Invalid 3", "localhost.cisco.com", "*.com", false},
            {"Invalid 9", "localhost.cisco.com", "localhost.c*.com", false},
            {"Invalid 10", "localhost.cisco.com", "localhost.*o.com", false},
            {"Invalid 11", "localhost.cisco.com", "localhost.c*o.com", false},
        };

        HashSet<String> suf = new HashSet<String>();
        suf.add(".com");

        for (Object[] j : v)
        {
            try
            {
                assertEquals(j[0].toString(), j[3], JsseDefaultHostnameAuthorizer.isValidNameMatch((String)j[1], (String)j[2], suf));
                fail("known suffix not caught");
            }
            catch (IOException e)
            {
                // expected
            }
        }
    }
}
