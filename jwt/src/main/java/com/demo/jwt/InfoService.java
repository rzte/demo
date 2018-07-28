package com.demo.jwt;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class InfoService {
    /**
     * 模拟获取用户列表
     * @return
     */
    public List<InfoModel> getInfoList(){
        List<InfoModel> list = new ArrayList<>(3);

        InfoModel infoModel = new InfoModel();
        infoModel.setUsername("admin");
        infoModel.setPassword("123456");
        infoModel.setRole("admin");
        infoModel.setLevel("11");
        list.add(infoModel);

        infoModel = new InfoModel();
        infoModel.setUsername("tom");
        infoModel.setPassword("abcabc");
        infoModel.setRole("normal");
        infoModel.setLevel("1");
        list.add(infoModel);

        infoModel = new InfoModel();
        infoModel.setUsername("bbc");
        infoModel.setPassword("abcabc");
        infoModel.setRole("normal");
        infoModel.setLevel("7");
        list.add(infoModel);

        return list;
    }

    public InfoModel getInfoModel(String username, String password){
        for(InfoModel infoModel : getInfoList()){
            if(infoModel.getUsername().equals(username) && infoModel.getPassword().equals(password)){
                return infoModel;
            }
        }
        return null;
    }
}
