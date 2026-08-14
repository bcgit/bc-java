package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.io.StreamOverflowException;

/**
 * Lives in the {@code org.bouncycastle.jce.provider} package so it can call the package-private
 * {@link OcspCache#getResponseSizeLimit} directly. The responder's Content-Length may narrow how
 * much of an OCSP response is read but must never widen it past our own ceiling.
 */
public class OcspCacheTest
    extends TestCase
{
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024;

    public String getName()
    {
        return "OcspCache";
    }

    public void testDefaultCeiling()
    {
        // a declared length beyond the ceiling is capped, not trusted
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(100 * 1024 * 1024));
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(Integer.MAX_VALUE));

        // absent Content-Length falls back to the ceiling, as it always did
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(-1));

        // a declared length within the ceiling still narrows the read
        assertEquals(0, OcspCache.getResponseSizeLimit(0));
        assertEquals(1024, OcspCache.getResponseSizeLimit(1024));
        assertEquals(DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(DEFAULT_MAX_RESPONSE_SIZE));
    }

    public void testConfiguredCeiling()
    {
        System.setProperty(Properties.OCSP_MAX_RESPONSE_SIZE, "4096");
        try
        {
            assertEquals(4096, OcspCache.getResponseSizeLimit(100 * 1024 * 1024));
            assertEquals(4096, OcspCache.getResponseSizeLimit(-1));
            assertEquals(100, OcspCache.getResponseSizeLimit(100));
        }
        finally
        {
            System.getProperties().remove(Properties.OCSP_MAX_RESPONSE_SIZE);
        }

        // a value that cannot be a size leaves the default in place rather than lifting the limit
        String[] unusable = new String[]{ "0", "-1" };
        for (int i = 0; i != unusable.length; i++)
        {
            System.setProperty(Properties.OCSP_MAX_RESPONSE_SIZE, unusable[i]);
            try
            {
                assertEquals("\"" + unusable[i] + "\" did not fall back to the default ceiling",
                    DEFAULT_MAX_RESPONSE_SIZE, OcspCache.getResponseSizeLimit(100 * 1024 * 1024));
            }
            finally
            {
                System.getProperties().remove(Properties.OCSP_MAX_RESPONSE_SIZE);
            }
        }
    }

    public void testOverLongResponseNamesTheLimit()
        throws Exception
    {
        byte[] tooMuch = new byte[100 * 1024];

        try
        {
            OcspCache.readResponse(new ByteArrayInputStream(tooMuch), 1024);
            fail("over-long OCSP response accepted");
        }
        catch (StreamOverflowException e)
        {
            // "Data Overflow" on its own says nothing about what was read or what to change
            assertEquals("OCSP response exceeds 1024 bytes (see org.bouncycastle.ocsp.max_response_size)",
                e.getMessage());
        }

        // a response within the limit is returned as it stands
        byte[] response = new byte[]{ 0x30, 0x03, 0x0a, 0x01, 0x00 };

        assertTrue(Arrays.areEqual(response, OcspCache.readResponse(new ByteArrayInputStream(response), 1024)));
    }
}
