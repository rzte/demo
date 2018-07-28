package com.demo.jwt;

import lombok.Data;

/**
 * 返回信息
 */
@Data
public class ResponseMsg {
    // 状态码
    private int code;

    // 返回信息
    private String msg;

    // 返回的数据
    private Object data;

    public ResponseMsg(int code, String msg, Object data){
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
}
