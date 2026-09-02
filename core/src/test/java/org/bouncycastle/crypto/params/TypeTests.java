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
            Object o = new HSSPrivateKeyParameters(1,
                Arrays.asList(lmsKey()), Collections.<LMSSignature>emptyList(), 1, 2);
            assertTrue(o == HSSPrivateKeyParameters.getInstance(o));
        }

        {
            Object o = new HSSPublicKeyParameters(0, new LMSPublicKeyParameters(null, null, null, null));
            assertTrue(o == HSSPublicKeyParameters.getInstance(o));
        }

        {
            Object o = lmsKey();
            assertTrue(o == LMSPrivateKeyParameters.getInstance(o));
        }

        {
            Object o = new LMSPublicKeyParameters(null, null, null, null);
            assertTrue(o == LMSPublicKeyParameters.getInstance(o));
        }
    }

    /**
     * The key parameter constructors validate their arguments, so these are real - the point of the
     * test is only that getInstance() hands back an object of its own type unchanged.
     */
    private static LMSPrivateKeyParameters lmsKey()
    {
        return new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5,
            LMOtsParameters.sha256_n32_w1, 0, new byte[16], 1 << LMSigParameters.lms_sha256_n32_h5.getH(),
            new byte[LMSigParameters.lms_sha256_n32_h5.getM()]);
    }
}
