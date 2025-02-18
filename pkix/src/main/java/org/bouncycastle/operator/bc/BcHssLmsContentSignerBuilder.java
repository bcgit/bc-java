package org.bouncycastle.operator.bc;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSSigner;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;

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

    static class HssSigner
        implements Signer
    {
        private MessageSigner signer;
        private final ByteArrayOutputStream stream = new ByteArrayOutputStream();

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
            stream.write(b);
        }

        @Override
        public void update(byte[] in, int off, int len)
        {
            stream.write(in, off, len);
        }

        @Override
        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            byte[] msg = stream.toByteArray();
            stream.reset();
            return signer.generateSignature(msg);
        }

        @Override
        public boolean verifySignature(byte[] signature)
        {
            byte[] msg = stream.toByteArray();
            stream.reset();
            return signer.verifySignature(msg, signature);
        }

        @Override
        public void reset()
        {
            stream.reset();
        }
    }
}
