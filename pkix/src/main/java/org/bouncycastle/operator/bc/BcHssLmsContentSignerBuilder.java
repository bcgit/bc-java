package org.bouncycastle.operator.bc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
import org.bouncycastle.util.Arrays;

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
        private final MessageSigner hss = new HSSSigner();
        private final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        private HSSPublicKeyParameters publicKeyParameters;
        static final byte tag_OctetString = 0x04;

        public HssSigner()
        {
        }

        @Override
        public void init(boolean forSigning, CipherParameters param)
        {
            hss.init(forSigning, param);
            if (forSigning)
            {
                publicKeyParameters = ((HSSPrivateKeyParameters)param).getPublicKey();
            }
            else
            {
                publicKeyParameters = (HSSPublicKeyParameters)param;
            }
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
            return hss.generateSignature(msg);
        }

        @Override
        public boolean verifySignature(byte[] signature)
        {
            byte[] msg = stream.toByteArray();
            stream.reset();
            return hss.verifySignature(msg, signature);
        }

        @Override
        public void reset()
        {
            stream.reset();
        }
    }
}
