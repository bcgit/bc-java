package org.bouncycastle.crypto.agreement.owl.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.owl.OwlAuthenticationFinish;
import org.bouncycastle.crypto.agreement.owl.OwlAuthenticationInitiate;
import org.bouncycastle.crypto.agreement.owl.OwlAuthenticationServerResponse;
import org.bouncycastle.crypto.agreement.owl.OwlClient;
import org.bouncycastle.crypto.agreement.owl.OwlClientRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlCurve;
import org.bouncycastle.crypto.agreement.owl.OwlCurves;
import org.bouncycastle.crypto.agreement.owl.OwlFinishRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlInitialRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlKeyConfirmation;
import org.bouncycastle.crypto.agreement.owl.OwlServer;
import org.bouncycastle.crypto.agreement.owl.OwlServerRegistration;
import org.bouncycastle.crypto.digests.SHA256Digest;


public class OwlServerTest
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
        new OwlServer(serverId, curve, digest, random);

        // null serverId
        try
        {
            new OwlServer(null, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null curve
        try
        {
            new OwlServer(serverId, null, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null digest
        try
        {
            new OwlServer(serverId, curve, null, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null random
        try
        {
            new OwlServer(serverId, curve, digest, null);
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
        OwlServer server = createServer();
        OwlClient client = createClient();
        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        OwlAuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        OwlAuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        server.authenticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        OwlKeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        OwlKeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);

        assertEquals(serverKeyingMaterial, clientKeyingMaterial);
    }

    public void testIncorrectPassword()
        throws CryptoException
    {
        OwlServer server = createServer();
        OwlClient client = createClientWithWrongPassword();

        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        OwlAuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        OwlAuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        try
        {
            server.authenticationServerEnd(clientLoginFinishPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testStateValidation()
        throws CryptoException
    {
        OwlServer server = createServer();
        OwlClient client = createClient();
        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        final OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        // START LOGIN INITIALISATION CHECKS
        assertEquals(OwlServer.STATE_INITIALISED, server.getState());

        final OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();

        // call server login end before login response should fail
        try
        {
            server.authenticationServerEnd(null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        OwlAuthenticationServerResponse serverLoginResponsePayload =
            server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        assertEquals(OwlServer.STATE_LOGIN_INITIALISED, server.getState());

        // create server login response twice should fail
        try
        {
            server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        final OwlAuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);

        // START LOGIN FINISH CHECKS
        // try calculate key before ending authentication server-side
        try
        {
            server.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        server.authenticationServerEnd(clientLoginFinishPayload);
        assertEquals(OwlServer.STATE_LOGIN_FINISHED, server.getState());

        // create server login end twice should fail
        try
        {
            server.authenticationServerEnd(clientLoginFinishPayload);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // START KEY CALCULATION CHECKS
        // Try initiate key confirmation before calculating key
        try
        {
            server.initiateKeyConfirmation(null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // Try to validate the key confirmation before calculating key.
        try
        {
            server.validateKeyConfirmation(null, null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger rawServerKey = server.calculateKeyingMaterial();
        assertEquals(OwlServer.STATE_KEY_CALCULATED, server.getState());

        // try calculate the key twice
        try
        {
            server.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger rawClientKey = client.calculateKeyingMaterial();

        // START KEY CONFIRMATION CHECKS

        OwlKeyConfirmation serverKC = server.initiateKeyConfirmation(rawServerKey);
        assertEquals(OwlServer.STATE_KC_INITIALISED, server.getState());

        try
        {
            server.initiateKeyConfirmation(null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        OwlKeyConfirmation clientKC = client.initiateKeyConfirmation(rawClientKey);

        server.validateKeyConfirmation(clientKC, rawServerKey);
        assertEquals(OwlServer.STATE_KC_VALIDATED, server.getState());

        client.validateKeyConfirmation(serverKC, rawClientKey);
    }

    public void testAuthenticationServerResponse()
        throws CryptoException
    {
        final OwlCurve curve = OwlCurves.NIST_P256;

        // Setup
        OwlInitialRegistration clientRegistrationPayload = createClientReg().initiateUserRegistration();
        final OwlFinishRegistration serverRegistrationPayload = createServerReg().registerUseronServer(clientRegistrationPayload);
        final OwlAuthenticationInitiate clientAuthInit = createClient().authenticationInitiate();

        // Should work
        createServer().authenticationServerResponse(clientAuthInit, serverRegistrationPayload);

        // serverId and clientId are the same
        try
        {
            createServer().authenticationServerResponse(
                new OwlAuthenticationInitiate(
                    "server",
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()),
                serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // g^x1 = infinity
        try
        {
            createServer().authenticationServerResponse(
                new OwlAuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    curve.getCurve().getInfinity(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()),
                serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // g^x2 = infinity
        try
        {
            createServer().authenticationServerResponse(
                new OwlAuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    curve.getCurve().getInfinity(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()),
                serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // g^x3 = infinity
        try
        {
            createServer().authenticationServerResponse(
                clientAuthInit,
                new OwlFinishRegistration(
                    serverRegistrationPayload.getClientId(),
                    serverRegistrationPayload.getKnowledgeProofForX3(),
                    curve.getCurve().getInfinity(),
                    serverRegistrationPayload.getPi(),
                    serverRegistrationPayload.getGt()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // zero knowledge proof for x1 fails
        final OwlAuthenticationInitiate clientAuthInit2 = createClient().authenticationInitiate();
        try
        {
            createServer().authenticationServerResponse(
                new OwlAuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit2.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()),
                serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // zero knowledge proof for x2 fails
        try
        {
            createServer().authenticationServerResponse(
                new OwlAuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit2.getKnowledgeProofForX2()),
                serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // clientId mismatch between payload and server registration
        try
        {
            createServer().authenticationServerResponse(
                clientAuthInit,
                new OwlFinishRegistration(
                    "server",
                    serverRegistrationPayload.getKnowledgeProofForX3(),
                    serverRegistrationPayload.getGx3(),
                    serverRegistrationPayload.getPi(),
                    serverRegistrationPayload.getGt()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testAuthenticationServerEnd()
        throws CryptoException
    {
        OwlServer server = createServer();
        OwlClient client = createClient();

        OwlAuthenticationFinish clientLoginFinishPayload = runExchangeUntilPass3(client, server);
        // should succeed
        server.authenticationServerEnd(clientLoginFinishPayload);

        final OwlServer server2 = createServer();
        OwlClient client2 = createClient();

        final OwlAuthenticationFinish clientLoginFinishPayload2 = runExchangeUntilPass3(client2, server2);

        // clientId is the same as serverId
        try
        {
            server2.authenticationServerEnd(new OwlAuthenticationFinish(
                "server",
                clientLoginFinishPayload2.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // clientId mismatch
        try
        {
            server2.authenticationServerEnd(new OwlAuthenticationFinish(
                "client2",
                clientLoginFinishPayload2.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload2.getR()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // validation fails: incorrect alpha
        final OwlAuthenticationFinish clientLoginFinishPayload3 = runExchangeUntilPass3(createClient(), createServer());
        try
        {
            server2.authenticationServerEnd(new OwlAuthenticationFinish(
                clientLoginFinishPayload2.getClientId(),
                clientLoginFinishPayload3.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload2.getR()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // validation fails: incorrect knowledge proof for alpha
        try
        {
            server2.authenticationServerEnd(new OwlAuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // validation fails: incorrect r value
        try
        {
            server2.authenticationServerEnd(new OwlAuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload2.getR()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    private OwlServer createServer()
    {
        return new OwlServer("server", OwlCurves.NIST_P256);
    }

    private OwlClient createClient()
    {
        return new OwlClient("client", "password".toCharArray(), OwlCurves.NIST_P256);
    }

    private OwlClient createClientWithWrongPassword()
    {
        return new OwlClient("client", "wrong".toCharArray(), OwlCurves.NIST_P256);
    }

    private OwlClientRegistration createClientReg()
    {
        return new OwlClientRegistration("client", "password".toCharArray(), OwlCurves.NIST_P256);
    }

    private OwlServerRegistration createServerReg()
    {
        return new OwlServerRegistration("server", OwlCurves.NIST_P256);
    }

    private OwlAuthenticationFinish runExchangeUntilPass3(OwlClient client, OwlServer server)
        throws CryptoException
    {
        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        OwlAuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        return client.authenticationFinish(serverLoginResponsePayload);
    }
}
