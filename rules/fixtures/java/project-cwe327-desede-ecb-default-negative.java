import java.util.Properties;

class SafeDefault {
    String read(Properties properties) {
        return properties.getProperty(
            "cryptoAlg1",
            "AES/GCM/NoPadding"
        );
    }
}
