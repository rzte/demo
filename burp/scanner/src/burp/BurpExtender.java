package burp;

import java.io.PrintStream;
import java.util.List;

/**
 * IScannerCheck：注册一个自定义的Scanner工具的检查器，Burp会告知检查器执行“主动扫描”或“被动扫描”，并在确认扫描问题时提供报告
 * IScannerListener: Scanner监听器，当Scanner工具扫描到新的问题时，会通知这个监听器。可以对扫描的问题进行自定义的分析记录
 */
public class BurpExtender implements IBurpExtender, IScannerCheck, IScannerListener{

    private IExtensionHelpers helpers = null;
    private PrintStream stdout = System.out;
    private PrintStream stderr = System.err;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintStream(callbacks.getStdout());
        stderr = new PrintStream(callbacks.getStderr());
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("scanner test");
        callbacks.registerScannerCheck(this);
        callbacks.registerScannerListener(this);
    }

    // ================================= ↓ IScannerCheck ↓ ===================================
    /**
     * 对每个请求调用此方法进行被动扫描
     * @param baseRequestResponse The base HTTP request / response that should
     * be passively scanned.
     * @return
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        stdout.print("doPassiveScan: ");
        stdout.println(helpers.analyzeRequest(baseRequestResponse).getUrl());
        stdout.println();
        return null;
    }

    /**
     * 为每个请求调用此方法进行主动扫描
     * @param baseRequestResponse The base HTTP request / response that should
     * be actively scanned.
     * @param insertionPoint An <code>IScannerInsertionPoint</code> object that
     * can be queried to obtain details of the insertion point being tested, and
     * can be used to build scan requests for particular payloads.
     * @return
     */
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        stdout.print("doActiveScan: ");
        stdout.println(helpers.analyzeRequest(baseRequestResponse).getUrl());
        stdout.print("insertionPoint: ");
        stdout.println(insertionPoint.getInsertionPointName());
        stdout.println();
        return null;
    }

    /**
     * 当自定义的Scanner工具的检查器针对同一个 URL 路径报告了多个扫描问题时，Scanner 工具会调用此方法
     * @param existingIssue An issue that was previously reported by this
     * Scanner check.
     * @param newIssue An issue at the same URL path that has been newly
     * reported by this Scanner check.
     * @return
     */
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        stdout.println("consolidateDuplicateIssues: ");
        stdout.print("existingIssue: ");
        stdout.println(existingIssue.getIssueName());
        stdout.print("newIssus: ");
        stdout.println(newIssue.getIssueName());
        stdout.println();
        return 0;
    }

    // ================================= ↓ IScannerListener ↓ ===================================
    /**
     * 当一个新的扫描问题被添加到Burp的Scanner工具的扫描结果中时，此方法会将被Burp调用
     * @param issue An
     * <code>IScanIssue</code> object that the extension can query to obtain
     */
    @Override
    public void newScanIssue(IScanIssue issue) {
        stdout.println("扫描到新的问题：");
        stdout.println("url => " + issue.getUrl());
        stdout.println("详情 => " + issue.getIssueDetail());
        stdout.println();
    }
}
