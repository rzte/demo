### JWT demo
---
```
- InfoModel
    model
- InfoService
    模拟生成数据
- JwtBuilder
    生成、解析token
- JwtController
    login登陆，返回token
    normal，任意登陆用户可访问
    level5，级别5以上用户访问
    admin，admin角色可访问
- ResponseMsg
    返回消息统一格式
- JwtApplication
    启动
```