package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.lms.HSSSigner;

public class BcHssLmsContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcHssLmsContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = digestProvider.get(digAlgId);

        return new HssSigner(dig);
    }

    private static class HssSigner
        implements Signer
    {
        private final MessageSigner hss = new HSSSigner();
        private final Digest digest;

        public HssSigner(Digest digest)
        {
            this.digest = digest;
        }

        @Override
        public void init(boolean forSigning, CipherParameters param)
        {
            hss.init(forSigning, param);
        }

        @Override
        public void update(byte b)
        {
            digest.update(b);
        }

        @Override
        public void update(byte[] in, int off, int len)
        {
            digest.update(in, off, len);
        }

        @Override
        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            return hss.generateSignature(hash);
        }

        @Override
        public boolean verifySignature(byte[] signature)
        {
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            return hss.verifySignature(hash, signature);
        }

        @Override
        public void reset()
        {
            digest.reset();
        }
    }
}
