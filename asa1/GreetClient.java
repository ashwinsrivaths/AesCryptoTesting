import java.net.*;
import java.io.*;

public class GreetClient {
    // private Socket clientSocket;
    // private PrintWriter out;
    // private BufferedReader in;

    // public void startConnection(String ip, int port) throws UnknownHostException,
    // IOException {
    // clientSocket = new Socket(ip, port);
    // out = new PrintWriter(clientSocket.getOutputStream(), true);
    // in = new BufferedReader(new
    // InputStreamReader(clientSocket.getInputStream()));
    // }

    // public String sendMessage(String msg) throws IOException {
    // out.println(msg);
    // String resp = in.readLine();
    // return resp;
    // }

    // public void stopConnection() throws IOException {
    // in.close();
    // out.close();
    // clientSocket.close();
    // }

    // public static void main(String[] args) throws IOException {
    // GreetClient client = new GreetClient();
    // client.startConnection("localhost", 6666);
    // client.sendMessage("msg//////////////");
    // }

    public static void main(String[] args) throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", 5001), 1000);
        System.out.println("Connection Successful!");

///////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Passing and Receiving messages
        DataInputStream dataIn = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream());
        dataOut.writeUTF("Hello, This is coming from Client111111111111!");
        String serverMessage = dataIn.readUTF();
        System.out.println(serverMessage);

        dataOut.writeUTF("Hello, This is coming from Client!22222222222222222222222222");

        
        serverMessage = dataIn.readUTF();
        System.out.println(serverMessage);



        dataIn.close();
        dataOut.close();
        socket.close();
    }
}