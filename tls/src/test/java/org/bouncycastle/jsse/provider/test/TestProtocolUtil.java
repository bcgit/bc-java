package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.Callable;

import junit.framework.Assert;
import org.bouncycastle.util.Strings;

class TestProtocolUtil
{
    public interface BlockingCallable
        extends Callable
    {
        void await() throws InterruptedException;
    }

    public static class Task
        implements Runnable
    {
        private final Callable callable;

        public Task(Callable callable)
        {
            this.callable = callable;
        }

        public void run()
        {
            try
            {
                callable.call();
            }
            catch (Exception e)
            {
                e.printStackTrace(System.err);
                if (e.getCause() != null)
                {
                    e.getCause().printStackTrace(System.err);
                }
            }
        }
    }

    public static void runClientAndServer(BlockingCallable server, BlockingCallable client)
        throws InterruptedException
    {
        new Thread(new TestProtocolUtil.Task(server)).start();
        server.await();

        new Thread(new TestProtocolUtil.Task(client)).start();
        client.await();
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
