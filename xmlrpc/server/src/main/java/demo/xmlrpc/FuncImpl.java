package demo.xmlrpc;

public class FuncImpl {
    public String hello(String name) {
        System.out.println("hello " + name);

        return "hello " + name;
    }

    public int add(int x, int y) {
        System.out.println("x + y = " + (x + y));
        return x + y;
    }

    /**
     * 这个方法不会被调用
     */
    public void run() {
        System.out.println("run............");
    }
}
