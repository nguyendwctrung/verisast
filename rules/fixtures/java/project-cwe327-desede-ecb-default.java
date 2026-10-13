import java.util.Properties;

class WeakDefault {
    String read(Properties properties) {
        // ruleid: project-cwe327-desede-ecb-default
        return properties.getProperty(
            "cryptoAlg1",
            "DESede/ECB/PKCS5Padding"
        );
    }
}
