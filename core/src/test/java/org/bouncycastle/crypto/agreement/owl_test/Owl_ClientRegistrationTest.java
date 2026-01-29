package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Owl_ClientRegistrationTest
{
	@Test
    public void testConstruction()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String clientId = "clientId";
        char[] password = "password".toCharArray();

        //should succeed
        assertDoesNotThrow(() ->
            new Owl_ClientRegistration(clientId, password, curve, digest, random)
        );

        //null clientId
        assertThrows(NullPointerException.class, () ->
            new Owl_ClientRegistration(null, password, curve, digest, random)
        );

        //null password
        assertThrows(NullPointerException.class, () ->
            new Owl_ClientRegistration(clientId, null, curve, digest, random)
        );

        //empty password
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_ClientRegistration(clientId, "".toCharArray(), curve, digest, random)
        );

        //null curve
        assertThrows(NullPointerException.class, () ->
            new Owl_ClientRegistration(clientId, password, null, digest, random)
        );

        //null digest
        assertThrows(NullPointerException.class, () ->
            new Owl_ClientRegistration(clientId, password, curve, null, random)
        );

        //null random
        assertThrows(NullPointerException.class, () ->
            new Owl_ClientRegistration(clientId, password, curve, digest, null)
        );
    }

    @Test 
    public void testSuccessfulExchange()
    {
    	Owl_ClientRegistration clientReg = createClientReg();
    	Owl_ServerRegistration serverReg = createServerReg();

    	Owl_InitialRegistration initialUserReg = assertDoesNotThrow(() -> 
    		clientReg.initiateUserRegistration()
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

    private Owl_ClientRegistration createClientReg()
    {
        return new Owl_ClientRegistration("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_ServerRegistration createServerReg()
    {
        return new Owl_ServerRegistration("server", Owl_Curves.NIST_P256);
    }
}