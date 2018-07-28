package com.demo.jwt;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
public class JwtController {

    private static final String SUCCESS = "success!";
    private static final String ERROR = "error!";

    @Autowired
    private InfoService infoService;

    @PostMapping("/login")
    public ResponseMsg login(@RequestParam("username") String username, @RequestParam("password") String password){
        InfoModel infoModel = infoService.getInfoModel(username, password);
        if(infoModel == null){  // 登陆失败
            return new ResponseMsg(400, ERROR, "login error");
        }

        //登陆成功，返回token
        Map<String, Object> map = new HashMap<>();
        map.put("username", infoModel.getUsername());
        map.put("level", infoModel.getLevel());
        map.put("role", infoModel.getRole());
        String token = JwtBuilder.generateToken(map);

        return new ResponseMsg(200, SUCCESS, token);
    }

    /**
     * 任意登陆用户
     * @param request
     * @return
     */
    @GetMapping("/normal")
    public ResponseMsg normal(HttpServletRequest request){
        String token = request.getHeader("Authorization");
        try {
            Claims claims = JwtBuilder.getClaimsFromToken(token);
            return new ResponseMsg(200, SUCCESS, claims);
        }catch (Exception e){
            return new ResponseMsg(400, ERROR, e.getMessage());
        }
    }

    /**
     * 级别5以上
     * @param request
     * @return
     */
    @GetMapping("/level5")
    public ResponseMsg level5(HttpServletRequest request){
        String token = request.getHeader("Authorization");
        try {
            Claims claims = JwtBuilder.getClaimsFromToken(token);
            Integer level = Integer.valueOf((String) claims.get("level"));
            if(level < 5){
                throw new RuntimeException("level error!");
            }
            return new ResponseMsg(200, SUCCESS, claims);
        }catch (Exception e){
            return new ResponseMsg(400, ERROR, e.getMessage());
        }
    }

    @GetMapping("/admin")
    public ResponseMsg admin(HttpServletRequest request){
        String token = request.getHeader("Authorization");
        try {
            Claims claims = JwtBuilder.getClaimsFromToken(token);
            String role = (String) claims.get("role");
            if(!"admin".equals(role)){
                throw new RuntimeException("role error!");
            }

            return new ResponseMsg(200, SUCCESS, claims);
        }catch (Exception e){
            return new ResponseMsg(400, ERROR, e.getMessage());
        }
    }
}
