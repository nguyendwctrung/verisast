import java.util.Properties;

class ProjectCwe327DesEdeEcbDefault {
    String configuredAlgorithm() {
        Properties properties = new Properties();
        return properties.getProperty("cryptoAlg1", "DESede/ECB/PKCS5Padding");
    }
}
