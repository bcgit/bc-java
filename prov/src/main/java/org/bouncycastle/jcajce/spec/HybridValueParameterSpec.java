package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.Destroyable;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec for the SP 800-56C Rev. 2 "hybrid" shared secret: the secret a
 * {@code KeyAgreement} derives keys from becomes Z' = Z || T, where Z is the agreement's own
 * shared secret and T is a secret established by some other scheme (SP 800-56C Rev. 2, Section
 * 2). NIST IR 8547, Section 3.2.1, names this generic composite as the way to combine a
 * classical key agreement with a post-quantum KEM during the transition to post-quantum
 * cryptography: T can be the shared secret of an ML-KEM encapsulation, and the result stays
 * secure while either component does.
 * <p>
 * The spec is accepted by every DH, ECDH and XDH {@code KeyAgreement} of the BC provider that
 * applies a KDF (the "...withSHA256KDF", "...withSHA256CKDF", "...withSHA256HKDF" and similar
 * services): {@code KeyAgreement.init(key, spec)} then {@code generateSecret(...)} derives the
 * keying material from Z' rather than Z, and the base spec supplies what the KDF would otherwise
 * have been given (for example a {@link UserKeyingMaterialSpec}). By default T is appended; with
 * {@code doPrepend} set the spec calculates Z' = T || Z instead, which NIST IR 8547 states will
 * also be allowed. The two orders give different keys, so the order is part of the protocol
 * being implemented and both parties must fix it in advance.
 * </p>
 * <pre>
 * // T from an ML-KEM encapsulation, Z from X25519
 * KeyAgreement agreement = KeyAgreement.getInstance("X25519withSHA256HKDF", "BC");
 * agreement.init(ourX25519Key, new HybridValueParameterSpec(mlkemSharedSecret, new UserKeyingMaterialSpec(ukm)));
 * agreement.doPhase(theirX25519Key, true);
 * SecretKey key = agreement.generateSecret("AES[256]");
 * </pre>
 * <p>
 * Get methods throw IllegalStateException if destroy() is called.
 * </p>
 */
public class HybridValueParameterSpec
    implements AlgorithmParameterSpec, Destroyable
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final boolean doPrepend;

    private volatile byte[] t;
    private volatile AlgorithmParameterSpec baseSpec;

    /**
     * Create a spec with T set to t and the spec for the KDF in the agreement to baseSpec.
     * Note: the t value is not copied.
     *
     * @param t a shared secret to be concatenated with the agreement's Z value.
     * @param baseSpec the base spec for the agreements KDF.
     */
    public HybridValueParameterSpec(byte[] t, AlgorithmParameterSpec baseSpec)
    {
        this(t, false, baseSpec);
    }

    /**
     * Create a spec with T set to t and the spec for the KDF in the agreement to baseSpec,
     * choosing which side of Z the value T goes on. Note: the t value is not copied.
     *
     * @param t a shared secret to be concatenated with the agreement's Z value.
     * @param doPrepend true to derive from T || Z, false to derive from Z || T.
     * @param baseSpec the base spec for the agreements KDF.
     */
    public HybridValueParameterSpec(byte[] t, boolean doPrepend, AlgorithmParameterSpec baseSpec)
    {
        this.t = t;
        this.baseSpec = baseSpec;
        this.doPrepend = doPrepend;
    }

    /**
     * Return whether or not T should be prepended.
     *
     * @return true if T to be prepended, false otherwise.
     */
    public boolean isPrependedT()
    {
        return doPrepend;
    }

    /**
     * Return a reference to the T value.
     *
     * @return a reference to T.
     */
    public byte[] getT()
    {
        byte[] tVal = t;

        checkDestroyed();
        
        return tVal;
    }

    /**
     * Return the base parameter spec.
     *
     * @return base spec to be applied to the KDF.
     */
    public AlgorithmParameterSpec getBaseParameterSpec()
    {
        AlgorithmParameterSpec rv = this.baseSpec;

        checkDestroyed();

        return rv;
    }

    /**
     * Return true if the destroy() method is called and the contents are
     * erased.
     *
     * @return true if destroyed, false otherwise.
     */
    public boolean isDestroyed()
    {
        return this.hasBeenDestroyed.get();
    }

    /**
     * Destroy this parameter spec, explicitly erasing its contents.
     */
    public void destroy()
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.clear(t);
            this.t = null;
            this.baseSpec = null;
        }
    }

    private void checkDestroyed()
    {
        if (isDestroyed())
        {
            throw new IllegalStateException("spec has been destroyed");
        }
    }
}
