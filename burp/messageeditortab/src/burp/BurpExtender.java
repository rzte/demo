package burp;

import java.awt.*;
import java.io.PrintStream;

/**
 * IMessageEditorTabFactory: 扩展插件可以在Burp的Http编辑器中渲染或编辑Http信息
 */
public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory{

    private PrintStream stdout = System.out;
    private PrintStream stderr = System.err;
    private IExtensionHelpers helpers = null;
    private IBurpExtenderCallbacks callbacks = null;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintStream(callbacks.getStdout());
        stderr = new PrintStream(callbacks.getStderr());
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("message editor tab");

        callbacks.registerMessageEditorTabFactory(this);
    }

    /**
     * Burp 将会对每一个 HTTP 消息编辑器调用一次此方法，此工厂必须返回一个新的 IMessageEditorTab 对象
     * @param controller An
     * <code>IMessageEditorController</code> object, which the new tab can query
     * to retrieve details about the currently displayed message. This may be
     * <code>null</code> for extension-invoked message editors where the
     * extension has not provided an editor controller.
     * @param editable Indicates whether the hosting editor is editable or
     * read-only.
     * @return
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new IMessageEditorTab() {

            // 文本编辑器
            private ITextEditor iTextEditor = callbacks.createTextEditor();

            @Override
            public String getTabCaption() {
                return "测试 MessageEditorTab";
            }

            /**
             * 设置组件，这里返回一个文本编辑器的组件
             * @return
             */
            @Override
            public Component getUiComponent() {
                return iTextEditor.getComponent();
            }

            /**
             *
             * @param content The message that is about to be displayed, or a zero-length
             * array if the existing message is to be cleared.
             * @param isRequest Indicates whether the message is a request or a
             * response.
             * @return
             */
            @Override
            public boolean isEnabled(byte[] content, boolean isRequest) {
                return isRequest;
            }

            /**
             *
             * @param content The message that is to be displayed, or
             * <code>null</code> if the tab should clear its contents and disable any
             * editable controls.
             * @param isRequest Indicates whether the message is a request or a
             */
            @Override
            public void setMessage(byte[] content, boolean isRequest) {
                // 把请求消息里的data参数进行Base64编码操作（content也可能为null，用的时候记得判断）
                try {
                    IParameter parameter = helpers.getRequestParameter(content, "data");
                    if(parameter != null){
                        stdout.print("name = ");
                        stdout.println(parameter.getName());
                        stdout.print("data = ");
                        stdout.println(parameter.getValue());
                        stdout.print("base64 = ");
                        stdout.println(helpers.base64Encode(parameter.getValue()));
                        stdout.println();
                    }
                }catch (Exception e){
                    stderr.println(e.getMessage());
                }

                iTextEditor.setText(content); // 设置展示的信息
            }

            /**
             * 要返回的信息
             * @return
             */
            @Override
            public byte[] getMessage() {
                return iTextEditor.getText();
            }

            /**
             * 是否允许用户修改当前的消息
             * @return
             */
            @Override
            public boolean isModified() {
                return true;
            }

            @Override
            public byte[] getSelectedData() {
                // 直接返回iTextEditor中选中的文本
                return iTextEditor.getSelectedText();
            }
        };
    }
}
