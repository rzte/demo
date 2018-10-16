package burp;

import java.io.IOException;
import java.io.PrintStream;

/**
 * 监听插件的状态（目前好像只有一个卸载）
 */
public class BurpExtender implements IBurpExtender, IExtensionStateListener{
    private PrintStream stdout = System.out;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintStream(callbacks.getStdout());
        callbacks.setExtensionName("state listener");
        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("unloaded ...");
        try {
            Runtime.getRuntime().exec("calc"); // 卸载时打开计算器
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
