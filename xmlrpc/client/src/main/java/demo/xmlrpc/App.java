package demo.xmlrpc;

import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;
import org.apache.xmlrpc.client.util.ClientFactory;

import java.net.URL;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {
        XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
        config.setServerURL(new URL("http://127.0.0.1:8080/"));

        config.setEnabledForExceptions(true);
        config.setBasicUserName("admin");
        config.setBasicPassword("123456");

        XmlRpcClient client = new XmlRpcClient();
        client.setConfig(config);

//        Object[] params = new Object[]{28, 30};
//        int result = (Integer)client.execute("demo.xmlrpc.Func.add", params);
//
//        System.out.println(result);

        ClientFactory factory = new ClientFactory(client);
        Func func = (Func)factory.newInstance(demo.xmlrpc.Func.class);

        System.out.println(func.add(1, 200));
    }
}
