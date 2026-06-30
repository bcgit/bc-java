package org.bouncycastle.crypto.agreement.owl.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.owl.OwlClientRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlCurve;
import org.bouncycastle.crypto.agreement.owl.OwlCurves;
import org.bouncycastle.crypto.agreement.owl.OwlInitialRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlServerRegistration;
import org.bouncycastle.crypto.digests.SHA256Digest;


public class OwlClientRegistrationTest
    extends TestCase
{
    public void testConstruction()
        throws CryptoException
    {
        OwlCurve curve = OwlCurves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String clientId = "clientId";
        char[] password = "password".toCharArray();

        // should succeed
        new OwlClientRegistration(clientId, password, curve, digest, random);

        // null clientId
        try
        {
            new OwlClientRegistration(null, password, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null password
        try
        {
            new OwlClientRegistration(clientId, null, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // empty password
        try
        {
            new OwlClientRegistration(clientId, "".toCharArray(), curve, digest, random);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // null curve
        try
        {
            new OwlClientRegistration(clientId, password, null, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null digest
        try
        {
            new OwlClientRegistration(clientId, password, curve, null, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null random
        try
        {
            new OwlClientRegistration(clientId, password, curve, digest, null);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }
    }

    public void testSuccessfulExchange()
        throws CryptoException
    {
        OwlClientRegistration clientReg = createClientReg();
        OwlInitialRegistration initialUserReg = clientReg.initiateUserRegistration();
        assertNotNull(initialUserReg);
    }

    public void testStateValidation()
        throws CryptoException
    {
        OwlClientRegistration clientReg = createClientReg();

        clientReg.initiateUserRegistration();

        // try call registration twice with the same client
        try
        {
            clientReg.initiateUserRegistration();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }
    }

    private OwlClientRegistration createClientReg()
    {
        return new OwlClientRegistration("client", "password".toCharArray(), OwlCurves.NIST_P256);
    }

    private OwlServerRegistration createServerReg()
    {
        return new OwlServerRegistration("server", OwlCurves.NIST_P256);
    }
}
