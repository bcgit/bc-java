package org.bouncycastle.pqc.crypto.aimer;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
/**
 * Implementation of the AIMer digital signature scheme as specified in the AIMer documentation.
 * This class provides low-level cryptographic operations for both signature generation and verification,
 * including finite field arithmetic over GF(2^128), GF(2^192), and GF(2^256), matrix generation,
 * MPC-based proofs, and the AIM2 block cipher.
 *
 * <p>AIMer is a <b>selected algorithm</b> in the <b>Korean Post-Quantum Cryptography (KPQC) project</b>.
 *
 * <p>References:</p>
 * <ul>
 *   <li><a href="https://aimer-signature.org/">AIMer Official Website</a></li>
 *   <li><a href="https://aimer-signature.org/docs/AIMer_Specification_v260130.pdf">AIMer Specification Document</a></li>
 *   <li><a href="https://github.com/samsungsds-research-papers/AIMer">AIMer Reference Implementation (unavailable right now)</a></li>
 * </ul>
 *
 * <p>This engine supports three security levels (128, 192, and 256 bits), each with fast and small variants.
 * The field size is automatically selected based on the provided {@link AIMerParameters}.</p>
 */
public class AIMerSigner
    implements MessageSigner
{
    private SecureRandom random;
    private AIMerParameters params;
    private AIMerPublicKeyParameters pubKey;
    private AIMerPrivateKeyParameters privKey;

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (AIMerPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (AIMerPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (AIMerPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        byte[] sig = new byte[params.getSignatureBytes()];
        AIMerEngine engine = new AIMerEngine(params);
        int result = engine.crypto_sign_signature(sig, message, message.length, privKey.getEncoded(), params, random);
        if (result != 0)
        {
            // returning an empty array here would be handed on as if it were a signature
            throw new IllegalStateException("unable to generate AIMer signature");
        }
        return sig;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        // An AIMer signature is exactly getSignatureBytes() long: a shorter buffer
        // would be indexed past its end, and accepting a longer one would make the
        // encoding non-unique - trailing bytes could be added to a valid signature
        // and it would still verify.
        if (signature.length != params.getSignatureBytes())
        {
            return false;
        }
        AIMerEngine engine = new AIMerEngine(params);
        return engine.crypto_sign_verify(signature, signature.length, message, message.length, pubKey.getEncoded(), params) == 0;
    }
}
