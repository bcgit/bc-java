package org.bouncycastle.crypto.params;

import java.util.Arrays;
import java.util.Collections;

import junit.framework.TestCase;
import org.bouncycastle.crypto.signers.lms.LMSSignature;

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
            Object o = new HSSPrivateKeyParameters(0,
                Arrays.asList(new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, new byte[32])),
                Collections.<LMSSignature>emptyList(), 1, 2);
            assertTrue(o == HSSPrivateKeyParameters.getInstance(o));
        }

        {
            Object o = new HSSPublicKeyParameters(0, new LMSPublicKeyParameters(null, null, null, null));
            assertTrue(o == HSSPublicKeyParameters.getInstance(o));
        }

        {
            Object o = new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, null);
            assertTrue(o == LMSPrivateKeyParameters.getInstance(o));
        }

        {
            Object o = new LMSPublicKeyParameters(null, null, null, null);
            assertTrue(o == LMSPublicKeyParameters.getInstance(o));
        }
    }
}
