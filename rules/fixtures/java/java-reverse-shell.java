import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

class JavaReverseShellNegative {
    void runLocalProcess(String[] command) throws Exception {
        // ok: java-reverse-shell
        Process process = new ProcessBuilder(command)
            .redirectErrorStream(true)
            .start();

        InputStream output = process.getInputStream();
        while (output.available() > 0) {
            System.out.write(output.read());
        }

        process.destroy();
    }

    void useClientSocket(String host, int port) throws Exception {
        // ok: java-reverse-shell
        Socket socket = new Socket(host, port);

        InputStream input = socket.getInputStream();
        OutputStream output = socket.getOutputStream();

        while (!socket.isClosed()) {
            while (input.available() > 0) {
                output.write(input.read());
            }
            output.flush();
            break;
        }

        socket.close();
    }

    void startProcessWithoutRedirect(String[] command) throws Exception {
        // ok: java-reverse-shell
        Process process = new ProcessBuilder(command).start();
        process.waitFor();
        process.destroy();
    }
}
