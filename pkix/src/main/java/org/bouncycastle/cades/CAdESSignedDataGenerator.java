package org.bouncycastle.cades;

import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * Marker subclass of {@link CMSSignedDataGenerator} for assembling CAdES
 * SignedData objects, giving CAdES-aware code a discoverable named entry
 * point. Use {@link CAdESSignerInfoGeneratorBuilder} to assemble the
 * per-signer generator and {@link #addSignerInfoGenerator} on this class to
 * attach it, then call {@code generate(...)} exactly as you would with a
 * plain {@code CMSSignedDataGenerator}.
 */
public class CAdESSignedDataGenerator
    extends CMSSignedDataGenerator
{
    /**
     * Base constructor.
     */
    public CAdESSignedDataGenerator()
    {
    }
}
