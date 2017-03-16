package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.Callable;

import org.bouncycastle.util.Strings;

import junit.framework.Assert;

class TestProtocolUtil
{
    public interface BlockingCallable
        extends Callable<Exception>
    {
        void await() throws InterruptedException;
    }

    public static class Task
        implements Runnable
    {
        private final Callable<Exception> callable;
        private Exception result = null;

        public Task(Callable<Exception> callable)
        {
            this.callable = callable;
        }

        public Exception getResult()
        {
            return result;
        }

        public void run()
        {
            try
            {
                result = callable.call();
            }
            catch (Exception e)
            {
                result = e;
            }
        }
    }

    public static void runClientAndServer(BlockingCallable server, BlockingCallable client)
        throws InterruptedException
    {
        TestProtocolUtil.Task serverTask = new TestProtocolUtil.Task(server);
        Thread serverThread = new Thread(serverTask);
        serverThread.start();
        server.await();

        TestProtocolUtil.Task clientTask = new TestProtocolUtil.Task(client);
        Thread clientThread = new Thread(clientTask);
        clientThread.start();
        client.await();

        serverThread.join();
        clientThread.join();

        Assert.assertNull(serverTask.getResult());
        Assert.assertNull(clientTask.getResult());
    }

    public static void doClientProtocol(
        Socket sock,
        String text)
        throws IOException
    {
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        writeMessage(text, out);

        String message = readMessage(in);

        Assert.assertEquals("World", message);
    }

    public static void doServerProtocol(
        Socket sock,
        String text)
        throws IOException
    {
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        String message = readMessage(in);

        writeMessage(text, out);

        Assert.assertEquals("Hello", message);
    }

    private static void writeMessage(String text, OutputStream out)
        throws IOException
    {
        out.write(Strings.toByteArray(text));
        out.write('!');
    }

    private static String readMessage(InputStream in)
        throws IOException
    {
        StringBuilder sb = new StringBuilder();

        int ch;
        while ((ch = in.read()) != '!')
        {
            sb.append((char)ch);
        }
        return sb.toString();
    }
}
