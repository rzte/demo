package com.demo.jwt;

import lombok.Data;

@Data
public class InfoModel {
    private String username;
    private String password;
    private String level;
    private String role;
}
