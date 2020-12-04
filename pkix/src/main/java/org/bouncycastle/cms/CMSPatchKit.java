package org.bouncycastle.cms;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Toolkit methods for dealing with common errors in CMS
 * classes.
 */
public class CMSPatchKit
{
    /**
     * Create a SignerInformation based on original which uses definite-length
     * rather than DER encoding for verifying the signature on the signed attributes.
     *
     * @param original the source SignerInformation
     */
    public static SignerInformation createNonDERSignerInfo(
        SignerInformation original)
    {
        return new DLSignerInformation(original);
    }

    /**
     * Create a SignerInformation based on original has it's signatureAlgorithm replaced
     * with the passed in AlgorithmIdentifier.
     *
     * @param original the source SignerInformation
     */
    public static SignerInformation createWithSignatureAlgorithm(
        SignerInformation original,
        AlgorithmIdentifier signatureAlgorithm)
    {
         return new ModEncAlgSignerInformation(original, signatureAlgorithm);
    }

    private static class DLSignerInformation
        extends SignerInformation
    {
        protected DLSignerInformation(SignerInformation baseInfo)
        {
            super(baseInfo);
        }

        public byte[] getEncodedSignedAttributes()
            throws IOException
        {
            return signedAttributeSet.getEncoded(ASN1Encoding.DL);
        }
    }

    private static class ModEncAlgSignerInformation
        extends SignerInformation
    {
        protected ModEncAlgSignerInformation(
            SignerInformation baseInfo,
            AlgorithmIdentifier signatureAlgorithm)
        {
            super(baseInfo, editEncAlg(baseInfo.info, signatureAlgorithm));
        }

        private static SignerInfo editEncAlg(SignerInfo info, AlgorithmIdentifier signatureAlgorithm)
        {
            return new SignerInfo(info.getSID(), info.getDigestAlgorithm(), info.getAuthenticatedAttributes(),
                signatureAlgorithm, info.getEncryptedDigest(), info.getUnauthenticatedAttributes());
        }
    }
}
