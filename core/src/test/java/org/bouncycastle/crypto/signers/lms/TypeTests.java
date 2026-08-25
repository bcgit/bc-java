package org.bouncycastle.crypto.signers.lms;

import junit.framework.TestCase;

/**
 * The getInstance methods of the engine's value classes are expected to return the instance
 * passed to them if it is already of the right type.
 */
public class TypeTests
    extends TestCase
{
    public void testTypeForType()
        throws Exception
    {
        {
            Object o = new HSSSignature(0, null, null);
            assertTrue(o == HSSSignature.getInstance(o, 0));
        }

        {
            Object o = new LMOtsPublicKey(null, null, 0, null);
            assertTrue(o == LMOtsPublicKey.getInstance(o));
        }

        {
            Object o = new LMOtsSignature(null, null, null);
            assertTrue(o == LMOtsSignature.getInstance(o));
        }

        {
            Object o = new LMSSignature(0, null, null, null);
            assertTrue(o == LMSSignature.getInstance(o));
        }
    }
}
