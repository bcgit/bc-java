package org.bouncycastle.pqc.crypto.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;

public class NTRUEncryptionParametersTest
    extends TestCase
{
    public void testLoadSave()
        throws IOException
    {
        NTRUEncryptionKeyGenerationParameters params = NTRUEncryptionKeyGenerationParameters.EES1499EP1;
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new NTRUEncryptionKeyGenerationParameters(is));
    }

    public void testEqualsHashCode()
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        NTRUEncryptionKeyGenerationParameters.EES1499EP1.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        NTRUEncryptionKeyGenerationParameters params = new NTRUEncryptionKeyGenerationParameters(is);

        assertEquals(params, NTRUEncryptionKeyGenerationParameters.EES1499EP1);
        assertEquals(params.hashCode(), NTRUEncryptionKeyGenerationParameters.EES1499EP1.hashCode());

        params.N += 1;
        assertFalse(params.equals(NTRUEncryptionKeyGenerationParameters.EES1499EP1));
        assertFalse(NTRUEncryptionKeyGenerationParameters.EES1499EP1.equals(params));
        assertFalse(params.hashCode() == NTRUEncryptionKeyGenerationParameters.EES1499EP1.hashCode());
    }

    public void testClone()
    {
        NTRUEncryptionKeyGenerationParameters params = NTRUEncryptionKeyGenerationParameters.APR2011_439;
        assertEquals(params, params.clone());

        params = NTRUEncryptionKeyGenerationParameters.APR2011_439_FAST;
        assertEquals(params, params.clone());
    }
}
