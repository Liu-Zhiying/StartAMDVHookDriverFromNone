# StartAMDVHookDriverFromNone
从0开始编写Windows AMD-V Hook 驱动的个人项目，可能会G，不定期上传参考资料和进度
## 原因
github看看，VTX的hook驱动满天飞，AMDV的呢？——没有，作为一个AMD用户能忍
## 进度
VT NPT HOOK 完成  
集成Intel XED库，可以识别函数指令长度方便HOOK  
修改_run_svm_vmrun函数，在VMM崩溃或中断时可以看到客户机调用栈   
可以通过VMP3.x检测   
## 已知问题
1. ~~Wow64程序在VT加载时会崩溃~~
2. ~~NPT页表和N卡驱动不兼容~~  
3. ~~系统运行部分程序（例如QQ NT）缓慢卡死，运行大量程序时蓝屏~~
4. ~~在 Release 模式 或者 使用 ExAllocatePoolWithTag 时会DPC超时~~ 
## 下一步计划
支持嵌套虚拟化  
将所有CPUID对VMM的调用改为vmmcall对VMM的调用  
实现64位用户态R3对Syscall hook的回调支持 
## 编译环境
VS222 + WDK 10
## 测试环境
Windows 11 24H2  
Windows 10 22h2  
## 联系（其实就是催更方式）
邮箱：1103660629@qq.com  
QQ：1103660629  
## 推荐项目（现在我学习的就这个）
https://github.com/tandasat/SimpleSvm  
https://github.com/tandasat/SimpleSvmHook  
## 引用的库
Intel XED https://github.com/intelxed/xed 修改见 XED Information 文件夹
## 文档
为了更快的下载代码，本仓库的文档移除，文档转移到另外一个仓库  
https://github.com/Liu-Zhiying/StartAMDVHookDriverFromNone_Documents  
## 如何使用SDK调用驱动功能
见FunctionTest.cpp  
## 暂停开发
本人需要准备考试，明年6月再开发