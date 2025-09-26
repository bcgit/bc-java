package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Owl_ServerTest
{
    @Test
    public void testConstruction()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String serverId = "serverId";

    // should succeed
    assertDoesNotThrow(() -> new Owl_Server(serverId, curve, digest, random));

    // null serverId
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(null, curve, digest, random));

    // null curve
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(serverId, null, digest, random));

    // null digest
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(serverId, curve, null, random));

    // null random
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(serverId, curve, digest, null));
    }

    @Test
    public void testSuccessfulExchange()
        throws CryptoException
    {

        Owl_Server server = createServer();
        Owl_Client client = createClient();
        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        server.authenticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);

        assertEquals(serverKeyingMaterial, clientKeyingMaterial);

    }

    @Test
    public void testIncorrectPassword()
        throws CryptoException
    {
        Owl_Server server = createServer();
        Owl_Client client = createClientWithWrongPassword();

        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        assertThrows(CryptoException.class, () -> 
            server.authenticationServerEnd(clientLoginFinishPayload)
        );
/*
        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        // Validate incorrect passwords result in a CryptoException
        assertThrows(CryptoException.class, () -> client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial));

        assertThrows(CryptoException.class, () -> server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial));*/
    }

    @Test
    public void testStateValidation() throws CryptoException {
        Owl_Server server = createServer();
        Owl_Client client = createClient();
        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        // START LOGIN INITIALISATION CHECKS
        assertEquals(Owl_Server.STATE_INITIALISED, server.getState());

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();

        // call server login end before login response should fail
        assertThrows(IllegalStateException.class, () -> server.authenticationServerEnd(null));

        Owl_AuthenticationServerResponse serverLoginResponsePayload =
            assertDoesNotThrow(() -> server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload));

        assertEquals(Owl_Server.STATE_LOGIN_INITIALISED, server.getState());

        // create server login response twice should fail
        assertThrows(IllegalStateException.class, () ->
            server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload));

        Owl_AuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);

        // START LOGIN FINISH CHECKS
        //try calculate key before ending authentication server-side
        assertThrows(IllegalStateException.class, server::calculateKeyingMaterial);

        assertDoesNotThrow(() -> server.authenticationServerEnd(clientLoginFinishPayload));
        assertEquals(Owl_Server.STATE_LOGIN_FINISHED, server.getState());

        // create server login end twice should fail
        assertThrows(IllegalStateException.class, () -> server.authenticationServerEnd(clientLoginFinishPayload));

        // START KEY CALCULATION CHECKS
        //Try initiate key confirmation before calculating key
        assertThrows(IllegalStateException.class, () -> server.initiateKeyConfirmation(null));
        // Try to validate the key confirmation before calculating key.
        assertThrows(IllegalStateException.class, () -> server.validateKeyConfirmation(null, null));

        BigInteger rawServerKey = assertDoesNotThrow(server::calculateKeyingMaterial);
        assertEquals(Owl_Server.STATE_KEY_CALCULATED, server.getState());
        // try calculate the key twice
        assertThrows(IllegalStateException.class, server::calculateKeyingMaterial);

        BigInteger rawClientKey = client.calculateKeyingMaterial();

        // START KEY CONFIRMATION CHECKS

        Owl_KeyConfirmation serverKC = assertDoesNotThrow(() -> server.initiateKeyConfirmation(rawServerKey));
        assertEquals(Owl_Server.STATE_KC_INITIALISED, server.getState());

        assertThrows(IllegalStateException.class, () -> server.initiateKeyConfirmation(null));

        Owl_KeyConfirmation clientKC = assertDoesNotThrow(() -> client.initiateKeyConfirmation(rawClientKey));

        assertDoesNotThrow(() -> server.validateKeyConfirmation(clientKC, rawServerKey));
        assertEquals(Owl_Server.STATE_KC_VALIDATED, server.getState());

        assertDoesNotThrow(() -> client.validateKeyConfirmation(serverKC, rawClientKey));
    }

    @Test
    public void testAuthenticationServerResponse() throws CryptoException {
        Owl_Curve curve = Owl_Curves.NIST_P256;

        // Setup
        Owl_InitialRegistration clientRegistrationPayload = createClientReg().initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = createServerReg().registerUseronServer(clientRegistrationPayload);
        Owl_AuthenticationInitiate clientAuthInit = createClient().authenticationInitiate();

        // Should work
        assertDoesNotThrow(() -> createServer().authenticationServerResponse(clientAuthInit, serverRegistrationPayload));

        // serverId and clientId are the same
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    "server",
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // g^x1 = infinity
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    curve.getCurve().getInfinity(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // g^x2 = infinity
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    curve.getCurve().getInfinity(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );
        // g^x3 = infinity
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                clientAuthInit,
                new Owl_FinishRegistration(
                    serverRegistrationPayload.getClientId(),
                    serverRegistrationPayload.getKnowledgeProofForX3(),
                    curve.getCurve().getInfinity(),
                    serverRegistrationPayload.getPi(),
                    serverRegistrationPayload.getGt()
                )
            )
        );
        // zero knowledge proof for x1 fails
        Owl_AuthenticationInitiate clientAuthInit2 = createClient().authenticationInitiate();
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit2.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // zero knowledge proof for x2 fails
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit2.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // clientId mismatch between payload and server registration
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                clientAuthInit,
                new Owl_FinishRegistration(
                    "server",
                    serverRegistrationPayload.getKnowledgeProofForX3(),
                    serverRegistrationPayload.getGx3(),
                    serverRegistrationPayload.getPi(),
                    serverRegistrationPayload.getGt()
                )
            )
        );
    }

    @Test
    public void testAuthenticationServerEnd() throws CryptoException {
        Owl_Server server = createServer();
        Owl_Client client = createClient();

        Owl_AuthenticationFinish clientLoginFinishPayload = runExchangeUntilPass3(client, server);
        // should succeed
        assertDoesNotThrow(() -> server.authenticationServerEnd(clientLoginFinishPayload));

        Owl_Server server2 = createServer();
        Owl_Client client2 = createClient();

        Owl_AuthenticationFinish clientLoginFinishPayload2 = runExchangeUntilPass3(client2, server2);
        // clientId is the same as serverId
        assertThrows(CryptoException.class, () ->
            server2.authenticationServerEnd(new Owl_AuthenticationFinish(
                "server",
                clientLoginFinishPayload2.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()
            ))
        );

        // clientId mismatch
        assertThrows(CryptoException.class, () ->
            server2.authenticationServerEnd(new Owl_AuthenticationFinish(
                "client2",
                clientLoginFinishPayload2.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload2.getR()
            ))
        );

        // validation fails: incorrect alpha
        Owl_AuthenticationFinish clientLoginFinishPayload3 = runExchangeUntilPass3(createClient(), createServer());
        assertThrows(CryptoException.class, () ->
            server2.authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload2.getClientId(),
                clientLoginFinishPayload3.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload2.getR()
            ))
        );

        // validation fails: incorrect knowledge proof for alpha
        assertThrows(CryptoException.class, () ->
            server2.authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()
            ))
        );

        // validation fails: incorrect r value
        assertThrows(CryptoException.class, () ->
            server2.authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload2.getR()
            ))
        );
    }

    private Owl_Server createServer()
    {
        return new Owl_Server("server", Owl_Curves.NIST_P256);
    }

    private Owl_Client createClient()
    {
        return new Owl_Client("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }

    private Owl_Client createClientWithWrongPassword()
    {
        return new Owl_Client("client", "wrong".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_ClientRegistration createClientReg()
    {
        return new Owl_ClientRegistration("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_ServerRegistration createServerReg()
    {
        return new Owl_ServerRegistration("server", Owl_Curves.NIST_P256);
    }
    private Owl_AuthenticationFinish runExchangeUntilPass3(Owl_Client client, Owl_Server server)
    throws CryptoException
    {
        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();
        
        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        return client.authenticationFinish(serverLoginResponsePayload);
    }
}