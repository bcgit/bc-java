package org.bouncycastle.pqc.crypto.lms;

import junit.framework.TestCase;

public class TypeTests
    extends TestCase
{

    /**
     * Get instance methods are expected to return the instance passed to them if it is the same type.
     *
     * @throws Exception
     */
    public void testTypeForType()
        throws Exception
    {
        {
            Object o = new HSSPrivateKeyParameters(0, new LMSPrivateKeyParameters[]{null}, new LMSSignature[0]);
            assert (o == HSSPrivateKeyParameters.getInstance(o, 0, 0));
        }

        {
            Object o = new HSSPublicKeyParameters(0, null);
            assert (o == HSSPublicKeyParameters.getInstance(o));
        }

        {
            Object o = new HSSSignature(0, null, null);
            assert (o == HSSSignature.getInstance(o, 0));
        }

        {
            Object o = new LMOtsPublicKey(null, null, 0, null);
            assert (o == LMOtsPublicKey.getInstance(o));
        }

        {
            Object o = new LMOtsSignature(null, null, null);
            assert (o == LMOtsSignature.getInstance(o));
        }

        {
            Object o = new LMSPrivateKeyParameters(null, null, 0, null, 0, null);
            assert (o == LMSPrivateKeyParameters.getInstance(o, 0));
        }

        {
            Object o = new LMSPublicKeyParameters(null, null, null, null);
            assert (o == LMSPublicKeyParameters.getInstance(o));
        }

        {
            Object o = new LMSSignature(0, null, null, null);
            assert (o == LMSSignature.getInstance(o));
        }


    }
}
