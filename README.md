# StartAMDVHookDriverFromNone
从0开始编写Windows AMD-V Hook 驱动的个人项目，可能会G，不定期上传参考资料和进度
## 原因
github看看，VTX的hook驱动满天飞，AMDV的呢？——没有，作为一个AMD用户能忍
## 进度
VT进入和退出代码基本完成
## 下一步计划
完善#VMEXIT处理函数，编写HOOK代码，编写页表代码
## 额外说明
目前Intel VT 驱动一般会同时使用EPT技术帮助进行内存管理，AMD 有对应的 NPT 但是考虑我的实际水平不高，可能选择放弃 NPT 而使用古老的影子页表
如果第一版没有使用 NPT 后面再加
## 联系（其实就是催更方式）
邮箱：1103660629@qq.com
QQ：1103660629
## 推荐项目（现在我学习的就这个）
https://github.com/tandasat/SimpleSvm
https://github.com/tandasat/SimpleSvmHook
