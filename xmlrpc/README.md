### (XML-RPC)[https://ws.apache.org/xmlrpc]

XML-RPC是通过http传输XML来实现远程过程调用，跨越不同操作系统，不同编程语言

### Server

对于服务端，要有一个`XMLRPCServer`对象来接收和执行`XML-RPC`调用。这个对象可以嵌入到servlet容器中或者HTTP服务器中。我在这里用`WebServer`

```java
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
        serverConfig.setEnabledForExtensions(true); // 如果服务端出现异常，则服务器将异常发送至客户端
        serverConfig.setContentLengthOptional(false); // 是否启用扩展

        webServer.start();
```

请求格式大概是这样的：

```xml
POST / HTTP/1.1
Content-Type: text/xml
User-Agent: Apache XML RPC 3.0 (Sun HTTP Transport)
Authorization: Basic YWRtaW46MTIzNDU2   # 此处为身份验证，默认格式是 `admin:password`的base64编码
Cache-Control: no-cache
Pragma: no-cache
Host: 172.17.0.2:8080
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Length: 235
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>demo.xmlrpc.Func.add</methodName>
  <params>
	<param>
		<value><int>10</int></value> <!-- 服务端接受的类型为int类型时，可以用int标签  -->
	</param>
	<param>
		<value><int>20</int></value>
	</param>
  </params>
</methodCall>
```

其返回信息格式如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse xmlns:ex="http://ws.apache.org/xmlrpc/namespaces/extensions">
  <params>
    <param>
      <value>
        <i4>30</i4>
      </value>
    </param>
  </params>
</methodResponse>
```

若设置了systemHandle，则可以使用系统的一些方法调用

```xml
POST / HTTP/1.1
Content-Type: text/xml
User-Agent: Apache XML RPC 3.0 (Sun HTTP Transport)
Authorization: Basic YWRtaW46MTIzNDU2
Cache-Control: no-cache
Pragma: no-cache
Host: 172.17.0.2:8080
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Length: 139
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>system.listMethods</methodName> <!-- 这个方法会返回所有接口函数 -->
  <params>
  </params>
</methodCall>
```

返回信息：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse xmlns:ex="http://ws.apache.org/xmlrpc/namespaces/extensions">
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>system.methodHelp</value>
            <value>system.methodSignature</value>
            <value>demo.xmlrpc.Func.add</value>
            <value>system.listMethods</value>
            <value>demo.xmlrpc.Func.hello</value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>
```

### Client

客户端的一些可用属性如下（具体查看官网）：

--- | ---
Property Name | Description
basicUserName | The user name, if your HTTP server requires basic authentication.
basicPassword | The user password, if your HTTP server requires basic authentication.
basicEncoding | Specifies the encoding being used to create the base 64 encoded Authorization header, which is being used for basic authentication. By default, the value of the encoding property is used. The encoding property itself defaults to UTF-8.


简单使用：

```java
        XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
        config.setServerURL(new URL("http://127.0.0.1:8080/"));

        config.setEnabledForExceptions(true);
        config.setBasicUserName("admin");
        config.setBasicPassword("123456");

        XmlRpcClient client = new XmlRpcClient();
        client.setConfig(config);

        Object[] params = new Object[]{28, 30};
        int result = (Integer)client.execute("Func.add", params);
        System.out.println(result);
```

还可以使用工厂类进行更方便的控制：

```java
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
        Func func = (Func)factory.newInstance(demo.xmlrpc.Func.class); // 此处的Func应为服务端提供的接口jar包

        System.out.println(func.add(1, 200));
```
