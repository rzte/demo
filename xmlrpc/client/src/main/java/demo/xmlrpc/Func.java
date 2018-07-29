package demo.xmlrpc;

/**
 * 服务端提供的接口
 */
public interface Func {
    String hello(String name);

    int add(int x, int y);

    void run();
}
