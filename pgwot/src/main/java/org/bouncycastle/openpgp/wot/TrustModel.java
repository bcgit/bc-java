package org.bouncycastle.openpgp.wot;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

/**
 * Trust-model specifying the policy and algorithm of trust/validity calculations.
 * <p>
 * OpenPGP/GnuPG supports multiple trust models. This implementation, however, currently supports {@link #PGP} only.
 */
public enum TrustModel
{
    CLASSIC(0, "classic"),
    PGP(1, "PGP"),
    EXTERNAL(2, "external"),
    ALWAYS(3, "always"),
    DIRECT(4, "direct");

    private final int numericId;
    private final String stringId;

    private static volatile TrustModel[] numericId2TrustModel;

    private TrustModel(int numericId, String stringId)
    {
        this.numericId = numericId;
        this.stringId = assertNotNull("stringId", stringId);
    }

    public int getNumericId()
    {
        return numericId;
    }

    public String getStringId()
    {
        return stringId;
    }

    @Override
    public String toString()
    {
        return stringId;
    }

    public static TrustModel fromNumericId(final int numericId) throws IllegalArgumentException
    {
        if (numericId < 0 || numericId >= getNumericId2TrustModel().length)
            throw new IllegalArgumentException("numericId unknown: " + numericId);

        final TrustModel trustModel = getNumericId2TrustModel()[numericId];
        if (trustModel == null)
            throw new IllegalArgumentException("numericId unknown: " + numericId);

        return trustModel;
    }

    private static TrustModel[] getNumericId2TrustModel()
    {
        if (numericId2TrustModel == null)
        {
            int maxNumericId = 0;
            for (final TrustModel trustModel : values())
                maxNumericId = Math.max(maxNumericId, trustModel.getNumericId());

            final TrustModel[] array = new TrustModel[maxNumericId + 1];
            for (final TrustModel trustModel : values())
                array[trustModel.getNumericId()] = trustModel;

            numericId2TrustModel = array;
        }
        return numericId2TrustModel;
    }

}
