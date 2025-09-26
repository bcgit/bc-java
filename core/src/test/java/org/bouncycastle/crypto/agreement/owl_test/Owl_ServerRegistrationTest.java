package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Owl_ServerRegistrationTest
{
	@Test
    public void testConstruction()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String serverId = "serverId";

        //should succeed
        assertDoesNotThrow(() ->
            new Owl_ServerRegistration(serverId, curve, digest, random)
        );

        //null serverId
        assertThrows(NullPointerException.class, () ->
            new Owl_ServerRegistration(null, curve, digest, random)
        );

        //null curve
        assertThrows(NullPointerException.class, () ->
            new Owl_ServerRegistration(serverId, null, digest, random)
        );

        //null digest
        assertThrows(NullPointerException.class, () ->
            new Owl_ServerRegistration(serverId, curve, null, random)
        );

        //null random
        assertThrows(NullPointerException.class, () ->
            new Owl_ServerRegistration(serverId, curve, digest, null)
        );
    }

    @Test 
    public void testSuccessfulExchange()
    {
    	Owl_ClientRegistration clientReg = createClientReg();
    	Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration initialUserReg = clientReg.initiateUserRegistration();
    	
        assertDoesNotThrow(() -> 
            serverReg.registerUseronServer(initialUserReg)
        );
    }

    @Test
    public void testStateValidation()
    {
    	Owl_ClientRegistration clientReg = createClientReg();
    	//Testing the client here only using the server for help
    	Owl_ServerRegistration serverReg = createServerReg();

    	Owl_InitialRegistration initialUserReg = assertDoesNotThrow(() -> 
    		clientReg.initiateUserRegistration()
    	);

    	//try call registration twice with the same client 

    	assertThrows(IllegalStateException.class, () -> 
            clientReg.initiateUserRegistration()
        );
    }

    @Test 
    public void testRegisterUseronServer()
    {
        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration initialUserReg = clientReg.initiateUserRegistration();
        
        //client and server ids are equal
        assertThrows(CryptoException.class, () -> serverReg.registerUseronServer(
            new Owl_InitialRegistration("server", initialUserReg.getPi(), initialUserReg.getGt()))
        );

        //pi is equal to 0
        assertThrows(CryptoException.class, () -> serverReg.registerUseronServer(
            new Owl_InitialRegistration(initialUserReg.getClientId(), BigInteger.valueOf(0), initialUserReg.getGt()))
        );

        //wrong gt
       /* Owl_ClientRegistration clientReg2 = new Owl_ClientRegistration("client2", "password2".toCharArray(), Owl_Curves.NIST_P256);
        Owl_InitialRegistration initialUserReg2 = clientReg2.initiateUserRegistration();
        assertThrows(CryptoException.class, () -> serverReg.registerUseronServer(
            new Owl_InitialRegistration(initialUserReg.getClientId(), initialUserReg.getPi(), initialUserReg2.getGt()))
        );*/
    }
    private Owl_ClientRegistration createClientReg()
    {
        return new Owl_ClientRegistration("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_ServerRegistration createServerReg()
    {
        return new Owl_ServerRegistration("server", Owl_Curves.NIST_P256);
    }
}