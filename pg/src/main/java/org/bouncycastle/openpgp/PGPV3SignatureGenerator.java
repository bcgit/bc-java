package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;

/**
 * Generator for old style PGP V3 Signatures.
 */
public class PGPV3SignatureGenerator
    extends PGPDefaultSignatureGenerator
{
    private PGPContentSignerBuilder contentSignerBuilder;
    private PGPContentSigner contentSigner;
    private int              providedKeyAlgorithm = -1;

    /**
     * Create a signature generator built on the passed in contentSignerBuilder.
     *
     * @param contentSignerBuilder  builder to produce PGPContentSigner objects for generating signatures.
     */
    public PGPV3SignatureGenerator(
        PGPContentSignerBuilder contentSignerBuilder)
    {
        this.contentSignerBuilder = contentSignerBuilder;
    }
    
    /**
     * Initialise the generator for signing.
     * 
     * @param signatureType
     * @param key
     * @throws PGPException
     */
    public void init(
        int           signatureType,
        PGPPrivateKey key)
        throws PGPException
    {
        if (signatureType == 0xFF)
        {
            throw new PGPException("Illegal signature type 0xFF provided.");
        }
        contentSigner = contentSignerBuilder.build(signatureType, key);
        sigOut = contentSigner.getOutputStream();
        sigType = contentSigner.getType();
        lastb = 0;

        if (providedKeyAlgorithm >= 0 && providedKeyAlgorithm != contentSigner.getKeyAlgorithm())
        {
            throw new PGPException("key algorithm mismatch");
        }
    }

    /**
     * Return the one pass header associated with the current signature.
     * 
     * @param isNested
     * @return PGPOnePassSignature
     * @throws PGPException
     */
    public PGPOnePassSignature generateOnePassVersion(
        boolean isNested)
        throws PGPException
    {
        return new PGPOnePassSignature(new OnePassSignaturePacket(sigType, contentSigner.getHashAlgorithm(), contentSigner.getKeyAlgorithm(), contentSigner.getKeyID(), isNested));
    }
    
    /**
     * Return a V3 signature object containing the current signature state.
     * 
     * @return PGPSignature
     * @throws PGPException
     */
    public PGPSignature generate()
        throws PGPException
    {
        long creationTime = new Date().getTime() / 1000;

        ByteArrayOutputStream sOut = new ByteArrayOutputStream();

        sOut.write(sigType);
        sOut.write((byte)(creationTime >> 24));
        sOut.write((byte)(creationTime >> 16));
        sOut.write((byte)(creationTime >> 8));
        sOut.write((byte)creationTime);

        byte[] hData = sOut.toByteArray();

        blockUpdate(hData, 0, hData.length);

        MPInteger[] sigValues;
        if (contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN
            || contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags.RSA_GENERAL)
            // an RSA signature
        {
            sigValues = new MPInteger[1];
            sigValues[0] = new MPInteger(new BigInteger(1, contentSigner.getSignature()));
        }
        else
        {
            sigValues = PGPUtil.dsaSigToMpi(contentSigner.getSignature());
        }

        byte[] digest = contentSigner.getDigest();
        byte[] fingerPrint = new byte[2];

        fingerPrint[0] = digest[0];
        fingerPrint[1] = digest[1];

        return new PGPSignature(new SignaturePacket(3, contentSigner.getType(), contentSigner.getKeyID(), contentSigner.getKeyAlgorithm(), contentSigner.getHashAlgorithm(), creationTime * 1000, fingerPrint, sigValues));
    }
}
