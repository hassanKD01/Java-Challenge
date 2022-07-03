/*
        used this class from the answer below with changes for decryption + signature verification
        https://stackoverflow.com/a/70647587
        "Swing is not thread and is single threaded."
        ...
        "One solution might be to use a SwingWorker.
        This allows you to perform long running or blocking operations within the context of their own threads,
        but provides a simple way to signal to the UI that changes have occurred safely."
 */

package javachallenge;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.SwingWorker;

public class ReadMessageWorker extends SwingWorker<Void, String> {

    public interface MessageListener {

        public void didRecieveMessage(String message);
    }

    private final DataInputStream dataInputStream;
    private final AtomicBoolean continueReading;
    private final MessageListener listener;
    private final PublicKey senderPublicKey;
    private final PrivateKey recieverPrivateKey;

    public ReadMessageWorker(DataInputStream dataInputStream, PublicKey senderPublicKey, PrivateKey recieverPrivateKey, MessageListener listener) {
        this.dataInputStream = dataInputStream;
        this.listener = listener;
        this.senderPublicKey = senderPublicKey;
        this.recieverPrivateKey = recieverPrivateKey;
        continueReading = new AtomicBoolean(true);
    }

    @Override
    protected void process(List<String> chunks) {
        for (String message : chunks) {
            listener.didRecieveMessage(message);
        }
    }

    public void stopReading() {
        continueReading.set(false);
        try {
            dataInputStream.close();
        } catch (IOException ex) {
        }
    }

    @Override
    protected Void doInBackground() throws Exception {
        while (continueReading.get()) {
                        
            byte result[] = new byte[512];
            dataInputStream.read(result);
            byte message [] = Arrays.copyOfRange(result, 0, result.length-256);
            byte signature[] = Arrays.copyOfRange(result, result.length-256, result.length);
            String text = RSAUtils.decrypt(message, recieverPrivateKey);
            
            if(!RSAUtils.verifySignature(signature, senderPublicKey, text)){
                text = "Failed To authenticate sender.";
            }
            
            //Sends data chunks to the process(List<String>) method.
            publish(text);
        }

        System.out.println("Read is now down...");

        return null;
    }
}
