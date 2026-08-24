package org.bouncycastle.operator.bc;


import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.HSSSigner;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.signers.LMSSigner;

/**
 * Builder for creating content signers that use the HSS/LMS Hash-Based Signature Algorithm.
 *
 * <b>Reference:</b> Use of the HSS/LMS Hash-Based Signature Algorithm in the Cryptographic Message Syntax (CMS)
 * <a href="https://datatracker.ietf.org/doc/rfc9708/">RFC 9708</a>.
 */
public class BcHssLmsContentSignerBuilder
    extends BcContentSignerBuilder
{
    private static final AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);

    public BcHssLmsContentSignerBuilder()
    {
        super(sigAlgId, null);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        return new HssSigner();
    }

    /**
     * Dispatches to the LMS or the HSS signer according to the key it is initialised with. Both
     * implement {@link Signer} directly, so this is a delegate rather than the message-buffering
     * adapter it used to be - the promoted org.bouncycastle.crypto.signers implementations buffer
     * the message themselves.
     */
    static class HssSigner
        implements Signer
    {
        private Signer signer;

        public HssSigner()
        {
        }

        @Override
        public void init(boolean forSigning, CipherParameters param)
        {
            if (param instanceof HSSPublicKeyParameters || param instanceof HSSPrivateKeyParameters)
            {
                signer = new HSSSigner();
            }
            else if (param instanceof LMSPublicKeyParameters || param instanceof LMSPrivateKeyParameters)
            {
                signer = new LMSSigner();
            }
            else
            {
                throw new IllegalArgumentException("Incorrect Key Parameters");
            }

            signer.init(forSigning, param);
        }

        @Override
        public void update(byte b)
        {
            signer.update(b);
        }

        @Override
        public void update(byte[] in, int off, int len)
        {
            signer.update(in, off, len);
        }

        @Override
        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            return signer.generateSignature();
        }

        @Override
        public boolean verifySignature(byte[] signature)
        {
            return signer.verifySignature(signature);
        }

        @Override
        public void reset()
        {
            signer.reset();
        }
    }
}
