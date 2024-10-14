# StartAMDVHookDriverFromNone
从0开始编写Windows AMD-V Hook 驱动的个人项目，可能会G，不定期上传参考资料和进度
## 原因
github看看，VTX的hook驱动满天飞，AMDV的呢？——没有，作为一个AMD用户能忍
## 进度
VT NPT HOOK 完成
## 已知问题
1. QQ音乐在VT加载时会崩溃  
2. ~~NPT页表和N卡驱动不兼容~~  
## 下一步计划
尝试修复已知问题
## 编译环境
VS222 + WDK 10
## 测试环境
Windows 11 24H2
## 联系（其实就是催更方式）
邮箱：1103660629@qq.com  
QQ：1103660629
## 推荐项目（现在我学习的就这个）WRITE_MSR_CPUID_SUBFUNCTION
https://github.com/tandasat/SimpleSvm  
https://github.com/tandasat/SimpleSvmHook
