package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * The class holds signature verifiers (e.g., for PQC)
 * and is able to build a TlsVerifier for the given public key.
 * <p>
 * #tls-injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedSigVerifiers
{

    public interface VerifySignatureFunction
    {
        boolean verifySignature(
                byte[] data,
                byte[] key,
                DigitallySigned signature);
    }

    private final Map<Integer, VerifySignatureFunction> verifiers; // code point -> verifier fn
    private final Map<Integer, PublicKeyToByteKey> converters; // code point -> encoder fn

    public InjectedSigVerifiers()
    {
        this.verifiers = new HashMap<>();
        this.converters = new HashMap<>();
    }

    public InjectedSigVerifiers(InjectedSigVerifiers origin)
    { // clone
        this.verifiers = new HashMap<>(origin.verifiers);
        this.converters = new HashMap<>(origin.converters);
    }

    public void add(
            int sigSchemeCodePoint,
            VerifySignatureFunction fn,
            PublicKeyToByteKey fn2)
    {
        verifiers.put(sigSchemeCodePoint, fn);
        converters.put(sigSchemeCodePoint, fn2);
    }

    public boolean contain(int sigSchemeCodePoint)
    {
        return verifiers.containsKey(sigSchemeCodePoint);
    }

    public TlsVerifier tlsVerifier(
            JcaTlsCrypto crypto,
            PublicKey publicKey,
            int sigSchemeCodePoint)
    {
        VerifySignatureFunction fn = verifiers.get(sigSchemeCodePoint);
        PublicKeyToByteKey fn2 = converters.get(sigSchemeCodePoint);

        return new MyTlsVerifier(crypto, publicKey, sigSchemeCodePoint, fn, fn2);
    }

    // implementing TlsVerifier via VerifySignatureFunction
    private class MyTlsVerifier
            implements TlsVerifier
    {
        private final JcaTlsCrypto crypto;
        private final PublicKey publicKey;
        private final int signatureScheme;
        private final VerifySignatureFunction fn;
        private final PublicKeyToByteKey fn2;

        public MyTlsVerifier(
                JcaTlsCrypto crypto,
                PublicKey publicKey,
                int signatureSchemeCodePoint,
                VerifySignatureFunction fn,
                PublicKeyToByteKey fn2)
        {
            if (null == crypto)
            {
                throw new NullPointerException("crypto");
            }
            if (null == publicKey)
            {
                throw new NullPointerException("publicKey");
            }
            if (!contain(signatureSchemeCodePoint))
            {
                throw new IllegalArgumentException("signatureSchemeCodePoint");
            }

            this.crypto = crypto;
            this.publicKey = publicKey;
            this.signatureScheme = signatureSchemeCodePoint;
            this.fn = fn;
            this.fn2 = fn2;
        }

        public boolean verifyRawSignature(
                DigitallySigned signature,
                byte[] hash) throws IOException
        {
            byte[] encoded = fn2.byteKey(publicKey);
            boolean b = fn.verifySignature(hash, encoded, signature);
            return b;
        }

        private class MyStreamVerifier
                implements TlsStreamVerifier
        {

            private final PublicKey publicKey;
            private final DigitallySigned signature;
            private final ByteArrayOutputStream stream;
            private final int signatureScheme;

            public MyStreamVerifier(
                    PublicKey publicKey,
                    DigitallySigned signature,
                    int signatureScheme)
            {
                this.publicKey = publicKey;
                this.signature = signature;
                this.stream = new ByteArrayOutputStream();
                this.signatureScheme = signatureScheme;
            }

            @Override
            public OutputStream getOutputStream() throws IOException
            {
                return this.stream;
            }

            @Override
            public boolean isVerified() throws IOException
            {

                byte[] data = this.stream.toByteArray();
                byte[] key = publicKey.getEncoded();

                int from = 0;
                int priorTo = key.length;


            /* if liboqs +JNI+DLL is used: // TODO
            if (this.signatureScheme==SignatureScheme.oqs_rainbowIclassic) {
                from = 24;
                Signature verifier = new Signature("Rainbow-I-Classic");
                key = Arrays.copyOfRange(key, from, priorTo);

                boolean b = verifier.verify(data, signature.getSignature(), key);
                verifier.dispose_sig();
                return b;
            }
            else*/
                /* for signatureScheme==SignatureScheme.oqs_sphincsshake256128frobust:
                    from = 26; // see der.md

                    SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
                    byte[] pubKey = Arrays.copyOfRange(key, from, priorTo);
                    SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters.shake256_128f, pubKey);
                    signer.init(false, params);
                    boolean b = signer.verifySignature(data, signature.getSignature());
                    return b;

                 */

                // the main functionality of MyTlsVerifier:
                return fn.verifySignature(data, key, signature);
            }
        }

        public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
        {
            return new MyStreamVerifier(this.publicKey, signature, this.signatureScheme);

        }
    }

}
