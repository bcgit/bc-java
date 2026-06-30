package org.bouncycastle.crypto.agreement.owl.test;

import java.math.BigInteger;
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


public class OwlServerRegistrationTest
    extends TestCase
{
    public void testConstruction()
        throws CryptoException
    {
        OwlCurve curve = OwlCurves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String serverId = "serverId";

        // should succeed
        new OwlServerRegistration(serverId, curve, digest, random);

        // null serverId
        try
        {
            new OwlServerRegistration(null, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null curve
        try
        {
            new OwlServerRegistration(serverId, null, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null digest
        try
        {
            new OwlServerRegistration(serverId, curve, null, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null random
        try
        {
            new OwlServerRegistration(serverId, curve, digest, null);
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
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration initialUserReg = clientReg.initiateUserRegistration();

        serverReg.registerUseronServer(initialUserReg);
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

    public void testRegisterUseronServer()
        throws CryptoException
    {
        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration initialUserReg = clientReg.initiateUserRegistration();

        // client and server ids are equal
        try
        {
            serverReg.registerUseronServer(
                new OwlInitialRegistration("server", initialUserReg.getPi(), initialUserReg.getGt()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // pi is equal to 0
        try
        {
            serverReg.registerUseronServer(
                new OwlInitialRegistration(initialUserReg.getClientId(), BigInteger.valueOf(0), initialUserReg.getGt()));
            fail();
        }
        catch (CryptoException e)
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
