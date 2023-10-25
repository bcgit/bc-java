package org.bouncycastle.tls.injection.sigalgs;

import lv.lumii.pqc.InjectablePQC;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Pack;

import java.io.IOException;
import java.util.Arrays;

public class MyMessageSigner implements MessageSigner {

    private SignatureAndHashAlgorithm algorithm;
    private SignerFunction fnSign;
    private VerifierFunction fnVerify;
    private CipherParametersToEncodedKey paramsToPublicKey, paramsToPrivateKey;

    // the following fields are initialized by BC by invoking init():
    private CipherParameters params;

    public MyMessageSigner(int signatureSchemeCodePoint,
                           SignerFunction fnSign, VerifierFunction fnVerify,
                           CipherParametersToEncodedKey paramsToPublicKey,
                           CipherParametersToEncodedKey paramsToPrivateKey) {
        this.algorithm = new SignatureAndHashAlgorithm((short) (signatureSchemeCodePoint >> 8), (short) (signatureSchemeCodePoint & 0xFF));
        this.fnSign = fnSign;
        this.fnVerify = fnVerify;
        this.paramsToPublicKey = paramsToPublicKey;
        this.paramsToPrivateKey = paramsToPrivateKey;
    }

    @Override
    public void init(boolean forSigning, CipherParameters param) {
        this.params = param;
    }


    @Override
    public byte[] generateSignature(byte[] message) {
        byte[] sk = this.paramsToPrivateKey.encodedKey(params); //skParams.getEncoded();

        byte[] bcSignature = new byte[0];
        try {
            bcSignature = fnSign.sign(null, message, sk); // TODO: do we need to pass crypto instead of null?
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return bcSignature;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature) {
        byte[] pk = this.paramsToPublicKey.encodedKey(params);
        return fnVerify.verify(message, pk, new DigitallySigned(algorithm, signature));
    }
}