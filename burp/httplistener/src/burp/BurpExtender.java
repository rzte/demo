package burp;

import java.io.PrintStream;

/**
 * Burp里任何一个工具发起http请求或收到http响应都会通知此监听器：IHttpListener
 * 代理监听： IProxyListener
 */
public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener{
    private PrintStream stdout = System.out;
    private PrintStream stderr = System.err;
    private IBurpExtenderCallbacks callbacks = null;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintStream(callbacks.getStdout());
        stderr = new PrintStream(callbacks.getStderr());
        this.callbacks = callbacks;

        callbacks.setExtensionName("http listener");
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
    }

    // ============================== ↓ IHttpListener ↓ ============================================

    @Override
    public void processHttpMessage(int toolFlag,  // 指示了发起请求或收到响应的Burp工具的ID（判断是在哪里，Repeater、Proxy、Scanner等），所有的toolFlag定义在IBurpExtenderCallbacks接口中
                                   boolean messageIsRequest, // 指示该消息是请求消息（True）还是响应消息（False）
                                   IHttpRequestResponse messageInfo // 被处理的消息的详细信息，是一个IHttpRequestResponse对象
    ) {
        switch (toolFlag){
            case IBurpExtenderCallbacks.TOOL_COMPARER:
                stdout.println("http ... compare ...");
                break;
            case IBurpExtenderCallbacks.TOOL_DECODER:
                stdout.println("http ... decoder ...");
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                stdout.println("http ... repeater ...");
                break;
            default:
                stdout.println("http ... other ...");
                break;
        }

        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
        if (requestInfo == null){
            stderr.println("requestInfo is null...");
            return;
        }

        stdout.print("request url: ");
        stdout.println(requestInfo.getUrl());
        stdout.println("\n");
    }

    // ============================== ↓ IProxyListener ↓ ============================================
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
//        if(messageIsRequest){
//            // Drop掉所有请求
//            message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
//            stdout.println("drop ... " + message.getMessageInfo());
//        }

        stdout.print("proxy");
        stdout.println("\n");
    }
}
