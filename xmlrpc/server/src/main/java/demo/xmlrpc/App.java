package demo.xmlrpc;

import org.apache.xmlrpc.XmlRpcRequest;
import org.apache.xmlrpc.common.XmlRpcHttpRequestConfig;
import org.apache.xmlrpc.metadata.XmlRpcSystemImpl;
import org.apache.xmlrpc.server.AbstractReflectiveHandlerMapping;
import org.apache.xmlrpc.server.PropertyHandlerMapping;
import org.apache.xmlrpc.server.XmlRpcServer;
import org.apache.xmlrpc.server.XmlRpcServerConfigImpl;
import org.apache.xmlrpc.webserver.WebServer;

/**
 * Hello world!
 *
 */
public class App 
{
    private static final int port = 8080;

    public static void main( String[] args ) throws Exception
    {
        WebServer webServer = new WebServer(port);

        XmlRpcServer xmlRpcServer = webServer.getXmlRpcServer();

        PropertyHandlerMapping phm = new PropertyHandlerMapping();
        phm.addHandler(Func.class.getName(), FuncImpl.class); // Func.*

        XmlRpcSystemImpl.addSystemHandler(phm); // system.*

        // 身份验证
        phm.setAuthenticationHandler(new AbstractReflectiveHandlerMapping.AuthenticationHandler() {
            @Override
            public boolean isAuthorized(XmlRpcRequest pRequest){
                XmlRpcHttpRequestConfig config = (XmlRpcHttpRequestConfig)pRequest.getConfig();

                return "admin".equals(config.getBasicUserName()) &&
                        "123456".equals(config.getBasicPassword());
            }
        });

        xmlRpcServer.setHandlerMapping(phm);

        XmlRpcServerConfigImpl serverConfig = (XmlRpcServerConfigImpl)xmlRpcServer.getConfig();
        serverConfig.setEnabledForExtensions(true);
        serverConfig.setContentLengthOptional(false);

        webServer.start();
    }
}
