package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintStream;

/**
 * Tab测试（页面上的标签）
 */
public class BurpExtender implements IBurpExtender, ITab{

    private PrintStream stdout = System.out;
    private JPanel jPanelMain = null;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // TODO Auto-generated method stub
        // set our extension name
        callbacks.setExtensionName("tab test");

        // obtain our output and error streams
        this.stdout = new PrintStream(callbacks.getStdout(), true);

        SwingUtilities.invokeLater(() -> {
            jPanelMain = new JPanel();
            JButton jButton = new JButton("click me");
            jButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    stdout.println("clicked...................");
                }
            });
            jPanelMain.add(jButton);

            // 设置自定义组件并添加标签
            callbacks.customizeUiComponent(jPanelMain);
            callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return "标签测试";
    }

    @Override
    public Component getUiComponent() {
        return jPanelMain;
    }
}
