# OS - Detector

课程大作业 主动操作系统指纹识别

用NodeJS的原因是：异步（载入指纹数据库，探测目标端口，发探针），写得舒服，函数式风格

简单用了用设计模式和函数式风格


## 结构设计

1. 控制模块：定时、顺序、异步调用发送模块，接受、合并嗅探模块的指纹信息

2. 发送模块：探针的发送

3. 嗅探模块：监听并分析探针的响应包

4. 探针模块：存储和管理探针


## 数据流图

![Stream](https://raw.githubusercontent.com/TangliziGit/os-detector/master/document/stream.png)


## 咋运行？

1. `sudo node index.js`

2. 访问3000端口
