package org.bouncycastle.est.jcajce;


import java.net.Socket;

/**
 * Channel Binding Provider provides a method of extracting the
 * ChannelBinding that can be customised specifically for the provider.
 * Presently JSSE does not support RFC 5920.
 * <p>
 * See https://bugs.openjdk.java.net/browse/JDK-6491070
 */
public interface ChannelBindingProvider
{
    boolean canAccessChannelBinding(Socket sock);

    byte[] getChannelBinding(Socket sock, String binding);
}
