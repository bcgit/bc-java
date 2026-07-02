package org.bouncycastle.pqc.crypto.qruov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

/**
 * QR-UOV signature implementation. Signing outputs the canonical
 * {@code signature || message} envelope per the reference NIST KAT format;
 * verification accepts a signature whose tail can carry the message.
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

        // The KAT envelope is signature || message
        return Arrays.concatenate(sigBytes, message);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        // Reject a signature shorter than one parameter-set signature: the
        // signature || message envelope must carry at least the signature, and
        // a shorter buffer would throw ArrayIndexOutOfBoundsException in the
        // arraycopy below.
        if (signature.length < params.getSignatureBytes())
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

        // Only the first signatureBytes of `signature` are the actual sig.
        int sigBytes = params.getSignatureBytes();
        byte[] sigOnly;
        if (signature.length == sigBytes)
        {
            sigOnly = signature;
        }
        else
        {
            sigOnly = new byte[sigBytes];
            System.arraycopy(signature, 0, sigOnly, 0, sigBytes);
        }

        byte[] sigR = new byte[saltLen];
        byte[][] sigS = new byte[N][L];
        engine.restoreSignature(sigOnly, sigR, sigS);

        return engine.verify(seedPk, P3, message, sigR, sigS);
    }
}
