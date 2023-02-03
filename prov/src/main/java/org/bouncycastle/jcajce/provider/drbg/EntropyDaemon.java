package org.bouncycastle.jcajce.provider.drbg;

import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

class EntropyDaemon
    implements Runnable
{
    private static final Logger LOG = Logger.getLogger(EntropyDaemon.class.getName());

    private final LinkedList<Runnable> tasks = new LinkedList<Runnable>();

    public EntropyDaemon()
    {
    }

    void addTask(Runnable task)
    {
        synchronized (tasks)
        {
            tasks.add(task);
        }
    }

    public void run()
    {
        while (!Thread.currentThread().isInterrupted())
        {
            Runnable task;
            synchronized (tasks)
            {
                task = tasks.poll();
            }

            if (task != null)
            {
                try
                {
                    task.run();
                }
                catch (Throwable e)
                {
                    // ignore
                }
            }
            else
            {
                try
                {
                    Thread.sleep(5000);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                }
            }
        }

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine("entropy thread interrupted - exiting");
        }
    }
}
