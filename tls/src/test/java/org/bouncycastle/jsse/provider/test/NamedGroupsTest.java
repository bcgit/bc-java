package org.bouncycastle.jsse.provider.test;

import java.security.KeyStore;
import java.security.Provider;

import javax.net.ssl.SSLContext;

import junit.framework.TestCase;

/**
 * Which named groups the BCJSSE provider offers when nothing has been configured.
 * <p/>
 * The pure ML-KEM groups are usable but must not be offered by default in either approved (FIPS)
 * or non-approved mode, following TLS working group feedback that a key exchange should retain a
 * classical component; the ML-KEM hybrids are defaults in both. A client restricted to one group
 * against a server left at its defaults answers the question directly: the handshake completes
 * only if the server offers that group without being told to.
 */
public class NamedGroupsTest
    extends TestCase
{
    private static final String[] PURE_MLKEM = new String[]{ "MLKEM512", "MLKEM768", "MLKEM1024" };

    private static final String[] MLKEM_HYBRID =
        new String[]{ "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768" };

    public void testPureMLKEMNotEnabledByDefaultNonApprovedMode()
        throws Exception
    {
        ProviderUtils.setupHighPriority(false);

        checkPureMLKEMNotDefault(ProviderUtils.getProviderBCJSSE(), "non-approved mode");
    }

    public void testPureMLKEMNotEnabledByDefaultApprovedMode()
        throws Exception
    {
        FipsTestUtils.setupFipsSuite();
        try
        {
            checkPureMLKEMNotDefault(ProviderUtils.getProviderBCJSSE(), "approved mode");
        }
        finally
        {
            FipsTestUtils.teardownFipsSuite();
        }
    }

    private void checkPureMLKEMNotDefault(Provider tlsProv, String mode)
        throws Exception
    {
        assertTrue(mode + ": expected a BCJSSE provider", ProviderUtils.isProviderBCJSSE(tlsProv));

        KeyStore[] credential = NamedGroupTestUtil.createRSACredential();
        KeyStore ks = credential[0], ts = credential[1];

        for (int i = 0; i != PURE_MLKEM.length; i++)
        {
            assertFalse(mode + ": " + PURE_MLKEM[i] + " reached a default-configured server",
                accepted(tlsProv, ks, ts, PURE_MLKEM[i]));
        }

        // the hybrids are defaults, which is also what shows the check above is not vacuous
        for (int i = 0; i != MLKEM_HYBRID.length; i++)
        {
            assertTrue(mode + ": " + MLKEM_HYBRID[i] + " refused by a default-configured server",
                accepted(tlsProv, ks, ts, MLKEM_HYBRID[i]));
        }
    }

    private static boolean accepted(Provider tlsProv, KeyStore ks, KeyStore ts, String namedGroup)
        throws Exception
    {
        SSLContext serverContext = NamedGroupTestUtil.createServerContext(tlsProv, ks);
        SSLContext clientContext = NamedGroupTestUtil.createClientContext(tlsProv, ts);

        return NamedGroupTestUtil.defaultServerAccepts(namedGroup, clientContext, serverContext);
    }
}
