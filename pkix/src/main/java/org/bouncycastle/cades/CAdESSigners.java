package org.bouncycastle.cades;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

/**
 * Package-private helper shared by the CAdES signer-upgrade paths
 * ({@link CAdESSignatureTimestampUtil}, {@link CAdESArchiveTimestampUtil}) so the
 * "rebuild the signer store, upgrading the matched signers" logic is single-sourced.
 */
class CAdESSigners
{
    private CAdESSigners()
    {
    }

    /**
     * Return a copy of {@code signedData} in which every signer contained in {@code matched}
     * has been replaced by {@code upgrade.apply(signer)} and all other signers are carried
     * through unchanged.
     *
     * @param signedData the source (left unchanged).
     * @param signers    its signer store ({@code signedData.getSignerInfos()}), passed in and
     *                   reused so the {@code matched} membership test sees the same
     *                   SignerInformation instances the caller selected.
     * @param matched    the signers to upgrade (a subset of {@code signers}).
     * @param upgrade    the per-signer transform applied to each matched signer.
     * @return a new CMSSignedData carrying the rebuilt signer store.
     */
    static CMSSignedData replaceMatched(CMSSignedData signedData, SignerInformationStore signers,
                                        Collection<SignerInformation> matched, Upgrade upgrade)
        throws CAdESException
    {
        List<SignerInformation> rebuilt = new ArrayList<SignerInformation>(signers.size());
        for (Iterator<SignerInformation> it = signers.getSigners().iterator(); it.hasNext(); )
        {
            SignerInformation cur = (SignerInformation)it.next();
            if (matched.contains(cur))
            {
                rebuilt.add(upgrade.apply(cur));
            }
            else
            {
                rebuilt.add(cur);
            }
        }

        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(rebuilt));
    }

    /**
     * Per-signer transform applied by {@link #replaceMatched} to each matched signer.
     */
    interface Upgrade
    {
        SignerInformation apply(SignerInformation signer)
            throws CAdESException;
    }
}
