## 滴水初级加密课项目 win10可用
win10 available

### 环境

vs2019 win32 c++等级preview

### 文件目录

LoadShell给shell加区段, 区段数据为demo

shell为壳

demo为源程序, 当然你可以用随便其他的

#### 问题

学了一点c++写法, 如果编译器不支持2019那么使用new即可

二者等同

```c++
shellPe = std::make_unique<Pe>(shellPath);
Pe shellPe = new Pe(shellPath);
```
#### 执行顺序
loadshell--->shell

### 待完成

- [ ] 增加对是否可以增加区段的判断
- [ ] 其它的Pe解析改变等(之前写的比较shi, 只弄了该小项目用到的几个)


