package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

public class ECPrivateKeyParameters
    extends ECKeyParameters
    implements Destroyable
{
    private BigInteger d;

    private volatile boolean destroyed;

    public ECPrivateKeyParameters(
        BigInteger          d,
        ECDomainParameters  parameters)
    {
        super(true, parameters);

        this.d = parameters.validatePrivateScalar(d);
    }

    public BigInteger getD()
    {
        BigInteger value = d;

        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }

        return value;
    }

    /**
     * Destroy this object, dropping its reference to the private value.
     * <p>
     * As {@link BigInteger} is immutable the private value cannot be zeroized in place;
     * destruction drops the internal reference so the value becomes unreachable (cleared on
     * garbage collection). After destruction {@link #getD()} throws
     * {@link IllegalStateException}.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            this.d = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }
}
