package org.bouncycastle.pqc.crypto.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.pqc.crypto.ntru.NTRUSigningKeyGenerationParameters;

public class NTRUSigningParametersTest
    extends TestCase
{

    public void testLoadSave()
        throws IOException
    {
        for (NTRUSigningKeyGenerationParameters params : new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
        {
            testLoadSave(params);
        }
    }

    private void testLoadSave(NTRUSigningKeyGenerationParameters params)
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new NTRUSigningKeyGenerationParameters(is));
    }

    public void testEqualsHashCode()
        throws IOException
    {
        for (NTRUSigningKeyGenerationParameters params : new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
        {
            testEqualsHashCode(params);
        }
    }

    private void testEqualsHashCode(NTRUSigningKeyGenerationParameters params)
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        NTRUSigningKeyGenerationParameters params2 = new NTRUSigningKeyGenerationParameters(is);

        assertEquals(params, params2);
        assertEquals(params.hashCode(), params2.hashCode());

        params.N += 1;
        assertFalse(params.equals(params2));
        assertFalse(params.equals(params2));
        assertFalse(params.hashCode() == params2.hashCode());
    }

    public void testClone()
    {
        for (NTRUSigningKeyGenerationParameters params : new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
        {
            assertEquals(params, params.clone());
        }
    }
}
