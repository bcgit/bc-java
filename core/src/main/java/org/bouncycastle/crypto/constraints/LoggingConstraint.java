package org.bouncycastle.crypto.constraints;

import java.util.Collections;
import java.util.Set;
import java.util.logging.Level;

import org.bouncycastle.crypto.CryptoServiceProperties;

/**
 * A constraint that refuses nothing and logs every service checked against it, at level INFO,
 * with its name, bits of security and purpose. The log is written through the
 * {@link java.util.logging.Logger} named for {@link ServicesConstraint}.
 */
public class LoggingConstraint
    extends ServicesConstraint
{
    /**
     * Log every service.
     */
    public LoggingConstraint()
    {
        this(Collections.EMPTY_SET);
    }

    /**
     * Log every service other than those named in the exceptions set.
     *
     * @param exceptions set of service names which are not logged.
     */
    public LoggingConstraint(Set<String> exceptions)
    {
        super(exceptions);
    }

    public void check(CryptoServiceProperties service)
    {
        if (isException(service.getServiceName()))
        {
            return;
        }

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info("service " + service.getServiceName() + " referenced [" + service.getServiceName() + ", " + service.bitsOfSecurity() + ", " + service.getPurpose() + "]");
        }
    }
}
