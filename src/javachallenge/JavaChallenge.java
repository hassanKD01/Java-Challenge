package javachallenge;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.beans.PropertyChangeEvent;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.xml.bind.DatatypeConverter;

public class JavaChallenge extends JPanel {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey senderPK;
    private ReadMessageWorker readWorker;
    private String name;

    DataInputStream inputStream;
    DataOutputStream outputStream;

    ServerSocket serverSocket;
    Socket socket;

    JTextField messageField;
    private JTextArea messageArea;

    private JButton send;

    
    public JavaChallenge() {
        setLayout(new BorderLayout());

        messageField = new JTextField(10);
        messageArea = new JTextArea(10, 20);

        messageField.addActionListener((ActionEvent e) -> {
            try {
                sendMessage(messageField.getText());
            } catch(NullPointerException ex) {
                JOptionPane.showMessageDialog(JavaChallenge.this, "Could not send message\nWaiting for public key", "Error", JOptionPane.ERROR_MESSAGE);                
            }
            catch (Exception ex) {
                JOptionPane.showMessageDialog(JavaChallenge.this, "Could not send message", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        add(new JScrollPane(messageArea));
        add(messageField, BorderLayout.NORTH);

        JPanel actionsPanel = new JPanel();
        send = new JButton("Send");

        send.addActionListener((ActionEvent e) -> {
            try {
                sendMessage(messageField.getText());
            }catch(NullPointerException ex) {
                JOptionPane.showMessageDialog(JavaChallenge.this, "Could not send message\nWaiting for public key", "Error", JOptionPane.ERROR_MESSAGE);                
            }
            catch (Exception ex) {
                JOptionPane.showMessageDialog(JavaChallenge.this, "Could not send message", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        actionsPanel.add(send);

        add(actionsPanel, BorderLayout.SOUTH);
    }

    //for concurrency problems with swing
    protected void appendMessage(String message) {
        if (!EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> {
                appendMessage(message);
            });
            return;
        }
        messageArea.append(message + "\n");
    }

    //for concurrency problems with swing solved using the answer linked in ReadMessageWorker
    protected void createMessageWorker(PublicKey senderPublicKey, PrivateKey recieverPrivateKey) {
        readWorker = new ReadMessageWorker(inputStream, senderPublicKey,recieverPrivateKey,
                //implementation of didRecieveMessage(String message) to append the recieved message to messageArea
                (String message) -> {
            appendMessage(message);
        });
        
        readWorker.addPropertyChangeListener((PropertyChangeEvent evt) -> {
            System.out.println(readWorker.getState());
            if (readWorker.getState() == SwingWorker.StateValue.DONE) {
                try {
                    readWorker.get();
                } catch (InterruptedException ex) {
                } catch (ExecutionException ex) {
                    JOptionPane.showMessageDialog(JavaChallenge.this, "Stopped reading due to error", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        readWorker.execute();
    }

    protected void sendMessage(String message) throws Exception {
        if (!(message == null || message.length() == 0)) {
            String text = name+":" + messageField.getText();
            
            if(senderPK == null){
                throw new NullPointerException();
            }
            
            byte[] cipherText = RSAUtils.Encrypt(text.getBytes(), senderPK);
            byte[] signatureBytes = RSAUtils.generateSignature(privateKey, text.getBytes());
            ByteArrayOutputStream output = new ByteArrayOutputStream();

            output.write(cipherText);
            output.write(signatureBytes);

            outputStream.write(output.toByteArray());
            appendMessage(text);
            messageField.setText(null);
        }
    }
    
    protected void start() {
        try {
            KeyPair keypair = RSAUtils.generateRSAKkeyPair();
            publicKey = keypair.getPublic();
            privateKey = keypair.getPrivate();
            
            try{
                socket = new Socket("127.0.0.1", 1234);
                appendMessage("Connected");
                name = "B";
            }catch(IOException ex){
                serverSocket = new ServerSocket(1234);
                name = "A";
                appendMessage("Waiting for someone to connect");
                socket = serverSocket.accept();
                appendMessage("Connected");
            }
            
            inputStream = new DataInputStream(socket.getInputStream());
            outputStream = new DataOutputStream(socket.getOutputStream());

            //Public key exchange
            outputStream.writeUTF(DatatypeConverter.printHexBinary(publicKey.getEncoded()));
            appendMessage("Waiting to acquire public key");
            senderPK = KeyFactory.getInstance("RSA")
                    .generatePublic(
                            new X509EncodedKeySpec(
                                    DatatypeConverter.parseHexBinary(
                                            inputStream.readUTF())));
            appendMessage("Public key acquired");
            
            createMessageWorker(senderPK, privateKey);
            
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            appendMessage("Port unavailable ...");
            System.exit(0);
        } catch (Exception ex) {
            Logger.getLogger(JavaChallenge.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        JavaChallenge panel = new JavaChallenge();
        JFrame frame = new JFrame();
        frame.setPreferredSize(new Dimension(400, 300));
        frame.add(panel);
        frame.pack();
        frame.setLocationByPlatform(true);
        frame.setVisible(true);
        panel.start();
    }
}
