package demo.xmlrpc;

public interface Func {
    String hello(String name);

    int add(int x, int y);

    /**
     * 这个方法不会被调用
     */
    void run();
}
