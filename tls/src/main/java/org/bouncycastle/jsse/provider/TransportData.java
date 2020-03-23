package org.bouncycastle.jsse.provider;

import java.net.Socket;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

class TransportData
{
    static TransportData from(Socket socket)
    {
        if (!(socket instanceof SSLSocket && socket.isConnected()))
        {
            return null;
        }

        SSLSocket sslSocket = (SSLSocket)socket;

        BCSSLParameters parameters = SSLSocketUtil.importSSLParameters(sslSocket);
        if (null == parameters)
        {
            /*
             * NOTE: For non-BCJSSE sockets, this could be null before JDK 1.6 (meaning neither
             * parameters nor handshake session exist). For backward compatibility, our
             * KeyManager/TrustManager implementations will behave as if no transport was provided.
             */
            return null;
        }

        BCExtendedSSLSession handshakeSession = SSLSocketUtil.importHandshakeSession(sslSocket);

        return new TransportData(parameters, handshakeSession);
    }

    static TransportData from(SSLEngine engine)
    {
        if (null == engine)
        {
            return null;
        }

        BCSSLParameters parameters = SSLEngineUtil.importSSLParameters(engine);
        if (null == parameters)
        {
            /*
             * NOTE: For non-BCJSSE engines, this could be null before JDK 1.6 (meaning neither
             * parameters nor handshake session exist). For backward compatibility, our
             * KeyManager/TrustManager implementations will behave as if no transport was provided.
             */
            return null;
        }

        BCExtendedSSLSession handshakeSession = SSLEngineUtil.importHandshakeSession(engine);

        return new TransportData(parameters, handshakeSession);
    }

    static BCAlgorithmConstraints getAlgorithmConstraints(TransportData transportData, boolean peerSigAlgs)
    {
        return null == transportData
            ?   ProvAlgorithmConstraints.DEFAULT
            :   transportData.getAlgorithmConstraints(peerSigAlgs);
    }

    private final BCSSLParameters parameters;
    private final BCExtendedSSLSession handshakeSession;

    private TransportData(BCSSLParameters parameters, BCExtendedSSLSession handshakeSession)
    {
        this.parameters = parameters;
        this.handshakeSession = handshakeSession;
    }

    BCSSLParameters getParameters()
    {
        return parameters;
    }

    BCExtendedSSLSession getHandshakeSession()
    {
        return handshakeSession;
    }

    BCAlgorithmConstraints getAlgorithmConstraints(boolean peerSigAlgs)
    {
        BCAlgorithmConstraints configAlgorithmConstraints = parameters.getAlgorithmConstraints();
        if (ProvAlgorithmConstraints.DEFAULT == configAlgorithmConstraints)
        {
            configAlgorithmConstraints = null;
        }

        if (null != handshakeSession && JsseUtils.isTLSv12(handshakeSession.getProtocol()))
        {
            String[] sigAlgsCert = peerSigAlgs
                ?   handshakeSession.getPeerSupportedSignatureAlgorithms()
                :   handshakeSession.getLocalSupportedSignatureAlgorithms();

            if (null != sigAlgsCert)
            {
                return new ProvAlgorithmConstraints(configAlgorithmConstraints, sigAlgsCert, true);
            }
        }

        return null == configAlgorithmConstraints
            ?   ProvAlgorithmConstraints.DEFAULT
            :   new ProvAlgorithmConstraints(configAlgorithmConstraints, true);
    }
}
