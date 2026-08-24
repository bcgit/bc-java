package org.bouncycastle.pqc.crypto.qruov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/**
 * QR-UOV signature implementation. Signing outputs the bare signature,
 * {@link QRUOVParameters#getSignatureBytes()} of them, and verification
 * requires exactly that. The reference NIST KAT files record the
 * {@code signature || message} "sm" envelope instead; that is a property of
 * the KAT harness rather than of the signature, and the test rebuilds it.
 */
public class QRUOVSigner
    implements MessageSigner
{
    private SecureRandom random;
    private QRUOVParameters params;
    private QRUOVPublicKeyParameters pubKey;
    private QRUOVPrivateKeyParameters privKey;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom pr = (ParametersWithRandom)param;
                privKey = (QRUOVPrivateKeyParameters)pr.getParameters();
                random = pr.getRandom();
            }
            else
            {
                privKey = (QRUOVPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (QRUOVPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        int seedLen = params.getSeedLen();
        int saltLen = params.getSaltLen();
        int L = params.getL();
        int N = params.getBigN();

        QRUOVEngine engine = new QRUOVEngine(params);

        byte[] sk = privKey.getEncoded();
        long[] pb = new long[]{0L};
        byte[] seedSk = new byte[seedLen];
        byte[] seedPk = new byte[seedLen];
        engine.restoreSeed(sk, pb, seedSk);
        engine.restoreSeed(sk, pb, seedPk);

        byte[] seedY = new byte[seedLen];
        byte[] seedR = new byte[seedLen];
        byte[] seedSol = new byte[seedLen];
        random.nextBytes(seedY);
        random.nextBytes(seedR);
        random.nextBytes(seedSol);

        byte[] sigR = new byte[saltLen];
        byte[][] sigS = new byte[N][L];

        engine.sign(seedSk, seedPk, seedY, seedR, seedSol, message, sigR, sigS);

        byte[] sigBytes = new byte[params.getSignatureBytes()];
        engine.storeSignature(sigR, sigS, sigBytes);

        return sigBytes;
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        // A QR-UOV signature is exactly getSignatureBytes() long, so require
        // that: a shorter buffer would be indexed past its end, and accepting a
        // longer one would make the encoding non-unique - trailing bytes could
        // be added to a valid signature and it would still verify.
        if (signature.length != params.getSignatureBytes())
        {
            return false;
        }
        int seedLen = params.getSeedLen();
        int saltLen = params.getSaltLen();
        int L = params.getL();
        int N = params.getBigN();
        int m = params.getM();
        int M = params.getBigM();

        QRUOVEngine engine = new QRUOVEngine(params);

        byte[] pkBytes = pubKey.getEncoded();
        long[] pb = new long[]{0L};
        byte[] seedPk = new byte[seedLen];
        engine.restoreSeed(pkBytes, pb, seedPk);

        byte[][][][] P3 = new byte[m][M][L][M];
        engine.restoreP3(pkBytes, pb, P3);

        byte[] sigR = new byte[saltLen];
        byte[][] sigS = new byte[N][L];
        // an F_q element outside [0, q), or a set padding bit after the last element, is a second
        // encoding of a signature that would otherwise verify - see restoreSignature
        if (!engine.restoreSignature(signature, sigR, sigS))
        {
            return false;
        }

        return engine.verify(seedPk, P3, message, sigR, sigS);
    }
}
