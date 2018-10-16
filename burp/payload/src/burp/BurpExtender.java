package burp;

import java.io.PrintStream;

/**
 * IIntruderPayloadGeneratorFactory： Intruder中的payload生成器
 * IIntruderPayloadProcessor： Intruder中的payload处理器
 */
public class BurpExtender implements IBurpExtender, IIntruderPayloadProcessor, IIntruderPayloadGeneratorFactory{

    private IExtensionHelpers helpers = null;
    PrintStream stdout = System.out;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        stdout = new PrintStream(callbacks.getStdout());

        callbacks.setExtensionName("payload");
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        callbacks.registerIntruderPayloadProcessor(this);
    }

    // ----------------------------------- ↓ 处理payload ↓ ---------------------------------------

    @Override
    public String getProcessorName() {
        return "process payload";
    }

    /**
     * 此方法由 Burp 调用，且会在每次使用一个 payload 发动攻击时都会调用一次此方法
     * @param currentPayload 当前已被处理过的 payload 的值
     * @param originalPayload 在应用处理规则之前的 payload 的原始值
     * @param baseValue payload 位置的基准值，将用当前已被处理过的 payload 替代
     * @return 返回已被处理过的 payload 的值。 如果返回 null 意味着当前的 payload 将被跳过,并且此次攻击将被直接移动到下一个 payload 。
     */
    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        stdout.print("currentPayload: ");
        stdout.println(helpers.bytesToString(currentPayload));

        stdout.print("originalPayload: ");
        stdout.println(helpers.bytesToString(originalPayload));

        stdout.print("baseValue: ");
        stdout.println(helpers.bytesToString(baseValue));

        stdout.println("\n");
        return new byte[0];
    }


    // ----------------------------------- ↓ 生成payload ↓ ---------------------------------------

    @Override
    public String getGeneratorName() {
        return "gen payload";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new IIntruderPayloadGenerator() {
            @Override
            public boolean hasMorePayloads() { // 此方法由 Burp 调用，用于决定 payload 生成器是否能够提供更多 payload
                return false;
            }

            @Override
            public byte[] getNextPayload(byte[] baseValue) { // 此方法由 Burp 调用，用于获取下一个 payload 的值
                stdout.print("gen payload: ");
                stdout.println(helpers.bytesToString(baseValue));
                return new byte[0];
            }

            @Override
            public void reset() { // 此方法由 Burp 调用，用于重置 payload 生成器的状态，这将导致下一次调用 getNextPayload() 方法时会返回

            }
        };
    }
}
