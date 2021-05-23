package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.util.test.SimpleTest;

public class PGPFeaturesTest
    extends SimpleTest
{
    public String getName()
    {
        return "FEATURES";
    }

    public void performTest()
        throws Exception
    {
        Features f = new Features(true, Features.FEATURE_MODIFICATION_DETECTION);
        isTrue(f.supportsFeature(Features.FEATURE_MODIFICATION_DETECTION));
        isTrue(f.supportsModificationDetection());
        isTrue(!f.supportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

        f = new Features(true, Features.FEATURE_VERSION_5_PUBLIC_KEY);
        isTrue(!f.supportsModificationDetection());
        isTrue(f.supportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

        f = new Features(true, Features.FEATURE_AEAD_ENCRYPTED_DATA);
        isTrue(f.supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        isTrue(!f.supportsModificationDetection());
        isTrue(!f.supportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

        f = new Features(true, Features.FEATURE_AEAD_ENCRYPTED_DATA | Features.FEATURE_MODIFICATION_DETECTION);
        isTrue(f.supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        isTrue(f.supportsModificationDetection());
        isTrue(!f.supportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));
        
        f = new Features(true, Features.FEATURE_VERSION_5_PUBLIC_KEY | Features.FEATURE_MODIFICATION_DETECTION);
        isTrue(!f.supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        isTrue(f.supportsModificationDetection());
        isTrue(f.supportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));
    }

    public static void main(
        String[]    args)
        throws Exception
    {
        runTest(new PGPFeaturesTest());
    }
}
