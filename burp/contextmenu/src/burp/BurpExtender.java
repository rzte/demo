package burp;

import javax.swing.*;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

/**
 * ContextMenu测试（右键时的菜单）
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory{

    private PrintStream stdout = System.out;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintStream(callbacks.getStdout());

        callbacks.setExtensionName("context menu");
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        stdout.println("createMenuItems ...");
        List<JMenuItem> jMenuItemList = new ArrayList<>();

        // 只在 Repeater 中点击右键时显示
        if(invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER){
            JMenu jMenu = new JMenu("父级菜单");// 父级菜单
            jMenuItemList.add(jMenu);

            // 子菜单
            JMenuItem menuItem = new JMenuItem("子菜单测试");
            jMenu.add(menuItem);
        }

        return jMenuItemList;
    }
}
