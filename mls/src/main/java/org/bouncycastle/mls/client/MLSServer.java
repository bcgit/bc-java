package org.bouncycastle.mls.client;

import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.IOException;

public class MLSServer
{
    public static void main(String[] args) throws IOException, InterruptedException
    {
        Server server1 = ServerBuilder.forPort(12346)
                .addService(new MLSClientImpl())
                .build();

        server1.start();
        server1.awaitTermination();
    }
}
