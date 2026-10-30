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
import org.bouncycastle.util.Strings;

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
 * Three fixed policies are available without dates: {@link #logOnly()} logs every use of a
 * quantum-vulnerable service and refuses nothing, {@link #legacyUseOnly()} refuses new protection
 * (key generation, signing, encryption and key agreement) while allowing verification and
 * decryption, and {@link #rejectAll()} refuses every use, legacy use included. One of them, or the
 * NIST timetable, can also be installed as the default constraint through the
 * {@link org.bouncycastle.util.Properties#CONSTRAINTS_QUANTUM_VULNERABLE} property; see
 * {@link #forPolicy(String)}.
 * </p>
 * <p>
 * Which services count as quantum-vulnerable is decided by
 * {@link ConstraintUtils#isQuantumVulnerable(CryptoServiceProperties)}; the post-quantum
 * algorithms (ML-KEM, ML-DSA, SLH-DSA, LMS/HSS, XMSS and the candidates) are never affected. Note
 * that a service reporting the purpose {@link CryptoServicePurpose#ANY} cannot be told from a
 * legacy use and is treated as one where legacy use is allowed.
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

    /**
     * The policy name selecting the NIST IR 8547 timetable, {@link #QuantumVulnerableConstraint()}.
     */
    public static final String POLICY_NIST = "nist";

    /**
     * The policy name selecting {@link #logOnly()}.
     */
    public static final String POLICY_LOG = "log";

    /**
     * The policy name selecting {@link #legacyUseOnly()}.
     */
    public static final String POLICY_LEGACY = "legacy";

    /**
     * The policy name selecting {@link #rejectAll()}.
     */
    public static final String POLICY_REJECT = "reject";

    /**
     * The policy name selecting no constraint at all.
     */
    public static final String POLICY_NONE = "none";

    private static final Date ALWAYS = new Date(0L);
    private static final Date NEVER = new Date(Long.MAX_VALUE);

    private final Date deprecatedAfter;
    private final Date disallowedAfter;
    private final boolean allowLegacyUse;
    private final boolean timetabled;

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
        this(deprecatedAfter, disallowedAfter, true, exceptions);
    }

    /**
     * Apply an explicit timetable, choosing whether legacy use survives the disallow date.
     *
     * @param deprecatedAfter the instant from which use of a quantum-vulnerable service is logged.
     * @param disallowedAfter the instant from which a quantum-vulnerable service is refused.
     * @param allowLegacyUse  true if verification and decryption are still allowed after the disallow
     *                        date, false if they are refused along with everything else.
     * @param exceptions      set of service names which are exceptions to the rules.
     */
    public QuantumVulnerableConstraint(Date deprecatedAfter, Date disallowedAfter, boolean allowLegacyUse, Set<String> exceptions)
    {
        this(deprecatedAfter, disallowedAfter, allowLegacyUse, exceptions, true);
    }

    private QuantumVulnerableConstraint(Date deprecatedAfter, Date disallowedAfter, boolean allowLegacyUse, Set<String> exceptions,
        boolean timetabled)
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
        this.allowLegacyUse = allowLegacyUse;
        this.timetabled = timetabled;
    }

    /**
     * Return a constraint that logs every use of a quantum-vulnerable service, at level INFO, and
     * refuses nothing.
     *
     * @return a log-only constraint.
     */
    public static QuantumVulnerableConstraint logOnly()
    {
        return logOnly(Collections.EMPTY_SET);
    }

    /**
     * Return a constraint that logs every use of a quantum-vulnerable service, at level INFO, and
     * refuses nothing.
     *
     * @param exceptions set of service names which are not logged.
     * @return a log-only constraint.
     */
    public static QuantumVulnerableConstraint logOnly(Set<String> exceptions)
    {
        return new QuantumVulnerableConstraint(ALWAYS, NEVER, true, exceptions, false);
    }

    /**
     * Return a constraint that refuses a quantum-vulnerable service for key generation, signing,
     * encryption and key agreement, and allows it, logged, for verification and decryption - the
     * SP 800-131A "legacy use".
     *
     * @return a legacy-use-only constraint.
     */
    public static QuantumVulnerableConstraint legacyUseOnly()
    {
        return legacyUseOnly(Collections.EMPTY_SET);
    }

    /**
     * Return a constraint that refuses a quantum-vulnerable service for key generation, signing,
     * encryption and key agreement, and allows it, logged, for verification and decryption - the
     * SP 800-131A "legacy use".
     *
     * @param exceptions set of service names which are not checked.
     * @return a legacy-use-only constraint.
     */
    public static QuantumVulnerableConstraint legacyUseOnly(Set<String> exceptions)
    {
        return new QuantumVulnerableConstraint(ALWAYS, ALWAYS, true, exceptions, false);
    }

    /**
     * Return a constraint that refuses every use of a quantum-vulnerable service, verification
     * and decryption included.
     *
     * @return a reject-all constraint.
     */
    public static QuantumVulnerableConstraint rejectAll()
    {
        return rejectAll(Collections.EMPTY_SET);
    }

    /**
     * Return a constraint that refuses every use of a quantum-vulnerable service, verification
     * and decryption included.
     *
     * @param exceptions set of service names which are not checked.
     * @return a reject-all constraint.
     */
    public static QuantumVulnerableConstraint rejectAll(Set<String> exceptions)
    {
        return new QuantumVulnerableConstraint(ALWAYS, ALWAYS, false, exceptions, false);
    }

    /**
     * Return the constraint a policy name selects: {@link #POLICY_NIST} for the NIST IR 8547
     * timetable, {@link #POLICY_LOG} for {@link #logOnly()}, {@link #POLICY_LEGACY} for
     * {@link #legacyUseOnly()}, {@link #POLICY_REJECT} for {@link #rejectAll()} and
     * {@link #POLICY_NONE} for no constraint. The names are case-insensitive and surrounding white
     * space is ignored. This is how the value of the
     * {@link org.bouncycastle.util.Properties#CONSTRAINTS_QUANTUM_VULNERABLE} property is read.
     *
     * @param policy the policy name.
     * @return the constraint, or null for {@link #POLICY_NONE}.
     * @throws IllegalArgumentException if the name is not one of the above.
     */
    public static QuantumVulnerableConstraint forPolicy(String policy)
    {
        String name = Strings.toLowerCase(policy.trim());

        if (name.equals(POLICY_NIST))
        {
            return new QuantumVulnerableConstraint();
        }
        if (name.equals(POLICY_LOG))
        {
            return logOnly();
        }
        if (name.equals(POLICY_LEGACY))
        {
            return legacyUseOnly();
        }
        if (name.equals(POLICY_REJECT))
        {
            return rejectAll();
        }
        if (name.equals(POLICY_NONE))
        {
            return null;
        }

        throw new IllegalArgumentException("unknown quantum-vulnerable policy: " + policy);
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
            if (LOG.isLoggable(Level.INFO))
            {
                LOG.info("usage of deprecated quantum-vulnerable service " + service.getServiceName()
                    + " for " + service.getPurpose());
            }
            return;
        }

        // compared with == rather than switched on, so the jdk1.4 build compiles this unchanged
        CryptoServicePurpose purpose = service.getPurpose();
        if (allowLegacyUse
            && (purpose == CryptoServicePurpose.ANY
                || purpose == CryptoServicePurpose.VERIFYING
                || purpose == CryptoServicePurpose.DECRYPTION
                || purpose == CryptoServicePurpose.VERIFICATION))
        {
            if (LOG.isLoggable(Level.INFO))
            {
                LOG.info("legacy use of disallowed quantum-vulnerable service " + service.getServiceName()
                    + " for " + purpose);
            }
            return;
        }

        throw new CryptoServiceConstraintsException("quantum-vulnerable service " + service.getServiceName()
            + " is disallowed for " + purpose + (timetabled ? " after " + disallowedAfter : ""));
    }

    private static Date startOfYear(int year)
    {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

        calendar.clear();
        calendar.set(year, Calendar.JANUARY, 1);

        return calendar.getTime();
    }
}
