package org.bouncycastle.crypto.constraints;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.TimeZone;
import java.util.logging.Level;

import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;

/**
 * A constraint on the quantum-vulnerable public-key algorithms (RSA, DSA, DH, EC and the
 * Edwards/Montgomery curve schemes, and the KEMs and key agreements built on them) following
 * the transition timetable of NIST IR 8547: a quantum-vulnerable service is allowed until the
 * deprecation date, allowed but logged between the deprecation date and the disallow date, and
 * refused after the disallow date except for "legacy use" - verification and decryption of data
 * protected earlier, which SP 800-131A continues to permit.
 * <p>
 * The no-argument constructor applies the NIST dates: deprecated after 2030, disallowed after
 * 2035. Any other policy is expressed by passing the dates explicitly; a date in the past
 * deprecates or disallows the algorithms immediately, a date far in the future turns that step
 * off. Services named in the exceptions set are not checked at all.
 * </p>
 * <p>
 * Which services count as quantum-vulnerable is decided by
 * {@link ConstraintUtils#isQuantumVulnerable(CryptoServiceProperties)}; the post-quantum
 * algorithms (ML-KEM, ML-DSA, SLH-DSA, LMS/HSS, XMSS and the candidates) are never affected. Note
 * that a service reporting the purpose {@link CryptoServicePurpose#ANY} cannot be told from a
 * legacy use and is treated as one.
 * </p>
 */
public class QuantumVulnerableConstraint
    extends ServicesConstraint
{
    /**
     * 1 January 2031, 00:00 UTC: NIST IR 8547 deprecates the quantum-vulnerable public-key
     * algorithms after 2030.
     */
    public static final Date NIST_DEPRECATED_AFTER = startOfYear(2031);

    /**
     * 1 January 2036, 00:00 UTC: NIST IR 8547 disallows the quantum-vulnerable public-key
     * algorithms after 2035.
     */
    public static final Date NIST_DISALLOWED_AFTER = startOfYear(2036);

    private final Date deprecatedAfter;
    private final Date disallowedAfter;

    /**
     * Apply the NIST IR 8547 timetable: deprecated after 2030, disallowed after 2035.
     */
    public QuantumVulnerableConstraint()
    {
        this(NIST_DEPRECATED_AFTER, NIST_DISALLOWED_AFTER, Collections.EMPTY_SET);
    }

    /**
     * Apply the NIST IR 8547 timetable with a set of service names that are not checked.
     *
     * @param exceptions set of service names which are exceptions to the rules.
     */
    public QuantumVulnerableConstraint(Set<String> exceptions)
    {
        this(NIST_DEPRECATED_AFTER, NIST_DISALLOWED_AFTER, exceptions);
    }

    /**
     * Apply an explicit timetable.
     *
     * @param deprecatedAfter the instant from which use of a quantum-vulnerable service is logged.
     * @param disallowedAfter the instant from which a quantum-vulnerable service is refused for
     *                        anything other than legacy use.
     */
    public QuantumVulnerableConstraint(Date deprecatedAfter, Date disallowedAfter)
    {
        this(deprecatedAfter, disallowedAfter, Collections.EMPTY_SET);
    }

    /**
     * Apply an explicit timetable with a set of service names that are not checked.
     *
     * @param deprecatedAfter the instant from which use of a quantum-vulnerable service is logged.
     * @param disallowedAfter the instant from which a quantum-vulnerable service is refused for
     *                        anything other than legacy use.
     * @param exceptions      set of service names which are exceptions to the rules.
     */
    public QuantumVulnerableConstraint(Date deprecatedAfter, Date disallowedAfter, Set<String> exceptions)
    {
        super(exceptions);

        if (deprecatedAfter == null || disallowedAfter == null)
        {
            throw new NullPointerException("dates cannot be null");
        }
        if (disallowedAfter.before(deprecatedAfter))
        {
            throw new IllegalArgumentException("disallowedAfter cannot precede deprecatedAfter");
        }

        this.deprecatedAfter = new Date(deprecatedAfter.getTime());
        this.disallowedAfter = new Date(disallowedAfter.getTime());
    }

    public void check(CryptoServiceProperties service)
    {
        if (!ConstraintUtils.isQuantumVulnerable(service) || isException(service.getServiceName()))
        {
            return;
        }

        Date now = new Date();
        if (now.before(deprecatedAfter))
        {
            return;
        }

        if (now.before(disallowedAfter))
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("usage of deprecated quantum-vulnerable service " + service.getServiceName()
                    + " for " + service.getPurpose());
            }
            return;
        }

        CryptoServicePurpose purpose = service.getPurpose();
        switch (purpose)
        {
        case ANY:
        case VERIFYING:
        case DECRYPTION:
        case VERIFICATION:
            if (LOG.isLoggable(Level.INFO))
            {
                LOG.info("legacy use of disallowed quantum-vulnerable service " + service.getServiceName()
                    + " for " + purpose);
            }
            return;
        }

        throw new CryptoServiceConstraintsException("quantum-vulnerable service " + service.getServiceName()
            + " is disallowed for " + purpose + " after " + disallowedAfter);
    }

    private static Date startOfYear(int year)
    {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

        calendar.clear();
        calendar.set(year, Calendar.JANUARY, 1);

        return calendar.getTime();
    }
}
