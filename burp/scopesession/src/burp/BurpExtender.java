package burp;

import java.io.PrintStream;

/**
 * IScopeChangeListener: 当 Burp 的 Target 工具下的 scope 发生变化时，将会通知此接口。
 * ISessionHandlingAction: 每一个已注册的会话操作动作在会话操作规则的UI中都是可用的，
 *     并且用户可以选择其中一个作为会话操作行为的规则。用户可以选择直接调用操作，也可以按照宏定义调用操作
 */
public class BurpExtender implements IBurpExtender, IScopeChangeListener, ISessionHandlingAction{

    private PrintStream stdout = System.out;
    private IExtensionHelpers helpers = null;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintStream(callbacks.getStdout());
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("scop session");
        callbacks.registerScopeChangeListener(this);
    }

    // ============================== ↓ ScopeChangeListener ↓ ======================================

    /**
     * 当Target下的scope发生变化时，会调用此方法
     */
    @Override
    public void scopeChanged() {
        stdout.println("scope changed!!");
    }

    // ============================== ↓ SessionHandlingAction ↓ ======================================

    /**
     * 此方法由 Burp 调用获取会话操作行为的名称
     * @return
     */
    @Override
    public String getActionName() {
        stdout.println("session getActionName");
        return "an action";
    }

    /**
     * 当会话操作行为被执行时会调用此方法
     * @param currentRequest The base request that is currently being processed.
     * The action can query this object to obtain details about the base
     * request. It can issue additional requests of its own if necessary, and
     * can use the setter methods on this object to update the base request.
     * @param macroItems If the action is invoked following execution of a
     * macro, this parameter contains the result of executing the macro.
     * Otherwise, it is
     * <code>null</code>. Actions can use the details of the macro items to
     * perform custom analysis of the macro to derive values of non-standard
     */
    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        stdout.print("performAction");
        stdout.println(helpers.analyzeRequest(currentRequest).getUrl());
        stdout.print("macroItems len: ");
        stdout.println(macroItems.length);
        stdout.println();
    }
}
