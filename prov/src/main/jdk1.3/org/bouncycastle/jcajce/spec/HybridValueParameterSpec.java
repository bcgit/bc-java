package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Arrays;


/*
 * SP 800-56C Hybrid Value spec, to allow the secret in a key agreement to be
 * created as "Z | T" where T is some other secret value as described in Section 2.
 */
public class HybridValueParameterSpec
    implements AlgorithmParameterSpec
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

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
        this.t = t;
        this.baseSpec = baseSpec;
    }

    /**
     * Return a reference to the T value.
     *
     * @return a reference to T.
     */
    public byte[] getT()
    {
        checkDestroyed();
        
        return t;
    }

    /**
     * Return the base parameter spec.
     *
     * @return base spec to be applied to the KDF.
     */
    public AlgorithmParameterSpec getBaseParameterSpec()
    {
        checkDestroyed();

        return baseSpec;
    }

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

    private static class AtomicBoolean
    {
        private volatile boolean value;

        AtomicBoolean(boolean value)
        {
            this.value = value;
        }

        public synchronized void set(boolean value)
        {
            this.value = value;
        }

        public synchronized boolean getAndSet(boolean value)
        {
            boolean tmp = this.value;

            this.value = value;

            return tmp;
        }

        public synchronized boolean get()
        {
            return this.value;
        }
    }
}
