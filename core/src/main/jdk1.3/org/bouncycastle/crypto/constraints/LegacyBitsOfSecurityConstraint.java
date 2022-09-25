package org.bouncycastle.crypto.constraints;

import java.util.Collections;
import java.util.Set;
//import java.util.logging.Level;

import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;

/**
 * Legacy bits of security constraint. By default, legacy algorithms are all acceptable but can only
 * be used for decryption and verification tasks. Algorithms with the required bits of security can be
 * used for anything. If a minimum level of security is given for legacy algorithms, then anything below
 * that will be treated as an error unless it appears in the exception list.
 */
public class LegacyBitsOfSecurityConstraint
    extends ServicesConstraint
{
    private final int requiredBitsOfSecurity;
    private final int legacyRequiredBitsOfSecurity;

    /**
     * Base constructor, legacy level is set to 0.
     *
     * @param requiredBitsOfSecurity required bits of security for encryption and signing operations.
     */
    public LegacyBitsOfSecurityConstraint(int requiredBitsOfSecurity)
    {
        this(requiredBitsOfSecurity, 0);
    }

    /**
     * Provide required bits of security and legacy requirements.
     *
     * @param requiredBitsOfSecurity required bits of security for encryption and signing operations.
     * @param legacyRequiredBitsOfSecurity acceptable bits of security for decryption and verification operations.
     */
    public LegacyBitsOfSecurityConstraint(int requiredBitsOfSecurity, int legacyRequiredBitsOfSecurity)
    {
        super(Collections.EMPTY_SET);

        this.requiredBitsOfSecurity = requiredBitsOfSecurity;
        this.legacyRequiredBitsOfSecurity = legacyRequiredBitsOfSecurity;
    }

    /**
     * Provide required bits of security, and a set of exceptions. Legacy requirement will default to 0.
     *
     * @param requiredBitsOfSecurity required bits of security for encryption and signing operations.
     * @param exceptions set service names which are exceptions to the above rules.
     */
    public LegacyBitsOfSecurityConstraint(int requiredBitsOfSecurity, Set<String> exceptions)
    {
        this(requiredBitsOfSecurity, 0, exceptions);
    }

    /**
     * Provide required bits of security, legacy requirements, and a set of exceptions.
     *
     * @param requiredBitsOfSecurity required bits of security for encryption and signing operations.
     * @param legacyRequiredBitsOfSecurity acceptable bits of security for decryption and verification operations.
     * @param exceptions set service names which are exceptions to the above rules.
     */
    public LegacyBitsOfSecurityConstraint(int requiredBitsOfSecurity, int legacyRequiredBitsOfSecurity, Set<String> exceptions)
    {
        super(exceptions);

        this.requiredBitsOfSecurity = requiredBitsOfSecurity;
        this.legacyRequiredBitsOfSecurity = legacyRequiredBitsOfSecurity;
    }

    public void check(CryptoServiceProperties service)
    {
        if (isException(service.getServiceName()))
        {
            return;
        }

        CryptoServicePurpose purpose = service.getPurpose();

        // ALL is allowed as we assume verifying/encryption will be blocked later.
        if (purpose.ordinal() == CryptoServicePurpose.ANY.ordinal()
           || purpose.ordinal() == CryptoServicePurpose.VERIFYING.ordinal()
           || purpose.ordinal() == CryptoServicePurpose.DECRYPTION.ordinal()
           || purpose.ordinal() == CryptoServicePurpose.VERIFICATION.ordinal())
       {
            if (service.bitsOfSecurity() < legacyRequiredBitsOfSecurity)
            {
                throw new CryptoServiceConstraintsException("service does not provide " + legacyRequiredBitsOfSecurity + " bits of security only " + service.bitsOfSecurity());
            }
            //if (purpose != CryptoServicePurpose.ANY && LOG.isLoggable(Level.FINE))
            //{
                //LOG.fine("usage of legacy cryptography service for algorithm " + service.getServiceName());
            //}
            return;
        }

        if (service.bitsOfSecurity() < requiredBitsOfSecurity)
        {
            throw new CryptoServiceConstraintsException("service does not provide " + requiredBitsOfSecurity + " bits of security only " + service.bitsOfSecurity());
        }
    }
}
