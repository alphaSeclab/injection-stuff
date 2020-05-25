# [所有收集类项目](https://github.com/alphaSeclab/all-my-collection-repos)




# Injection


- PE注入、DLL注入、进程注入、线程注入、代码注入、Shellcode注入、ELF注入、Dylib注入，当前包括400+工具和350+文章，根据功能进行了粗糙的分类
- [English Version](https://github.com/alphaSeclab/injection-stuff/blob/master/Readme_en.md)


# 目录
- [PE注入](#81a3947baa3f99adaf73a8f9766e48fa) ->  [(9)工具](#2642c767c5d89e80c90310fb74e6edb3) [(6)文章](#f7498d4f9350180b46ad63bedae4ea1b)
- [DLL注入](#4df0a2fb37f3cafbdaef103e982a1b0a)
    - [(1) 集合](#4ba9c31b7264396cd7666e6b4a29b3dd)
    - [(70) 工具](#f7a55b191aab1cb7a57fe44d94b54e1c)
    - [(92) 文章](#f69bdae6414fe41f7b2ff0a5ae646e0e)
- [进程注入](#97ceb80739f1d2efce08baaf98dce0fc) ->  [(48)工具](#5ed3d284b106ffdc141f447f59326b00) [(92)文章](#78df9ff3771ac1e9d9dff3eba0055d25)
- [线程注入](#3b2252d379d384475de4654bd5d0b368) ->  [(1)工具](#9ff33dd10584407a654590a7cf18c6f0) [(9)文章](#a7433a31e0f33f936d15d6ad61437bc6)
- [代码注入](#02a1807b6a7131af27e3ed1002e7335a) ->  [(47)工具](#303ed79296c5af9c74cfd49dd31a399e) [(143)文章](#5e603e03f62d50e6fa8310e15470f233)
- [Shellcode注入](#a5458e6ee001b754816237b9a2108569) ->  [(13)工具](#28e1b534eae8d37d8fc1d212f0db0263) [(26)文章](#c6942bb5275f5b62a41238c6042b2b81)
- [ELF注入](#3584002eaa30b92479c1e1c2fc6ce4ef) ->  [(7)工具](#b423b830472372349203f88cf64c6814) [(8)文章](#0a853f9e3f9ccb0663007d3a508ce02b)
- [Dylib注入](#108c798de24e7ce6fde0cafe99eec5b3) ->  [(5)工具](#12df48702564d73c275c72133546d73e) [(1)文章](#0af1332c6476d1a8f98046542e925282)
- [Android](#06fc9c584b797f97731e3c49886dcc08) ->  [(21)工具](#4c02a0ba65fa4f582ec590ce1e070822) [(10)文章](#9ff27f3143a5c619b554185069ecffb0)
- [其他](#4ffa5c3eb1f3b85e4c38f6863f5b76b2) ->  [(190)工具](#fd5f8ada2d4f47c63c3635427873c79c) [(2)文章](#7004b87c5ab514b352dd7cc91acdd17b)


# <a id="81a3947baa3f99adaf73a8f9766e48fa"></a>PE注入


***


## <a id="2642c767c5d89e80c90310fb74e6edb3"></a>工具


- [**535**星][20d] [C] [jondonym/peinjector](https://github.com/jondonym/peinjector) peinjector - MITM PE file infector
- [**407**星][5m] [Assembly] [hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) 将PE文件转换为Shellcode
- [**230**星][3y] [C++] [secrary/infectpe](https://github.com/secrary/infectpe) Inject custom code into PE file [This project is not maintained anymore]
- [**220**星][2y] [C++] [bromiumlabs/packerattacker](https://github.com/bromiumlabs/packerattacker) C++ application that uses memory and code hooks to detect packers
- [**196**星][30d] [Py] [antonin-deniau/cave_miner](https://github.com/antonin-deniau/cave_miner) Search for code cave in all binaries
- [**126**星][3y] [C++] [gpoulios/ropinjector](https://github.com/gpoulios/ropinjector) 将ROP编码的shellcode打补丁到PE文件中
- [**119**星][16d] [C] [hasherezade/chimera_pe](https://github.com/hasherezade/chimera_pe) ChimeraPE (a PE injector type - alternative to: RunPE, ReflectiveLoader, etc) - a template for manual loading of EXE, loading imports payload-side
- [**119**星][16d] [C] [hasherezade/chimera_pe](https://github.com/hasherezade/chimera_pe) 一种PE注入器类型-可替代:RunPE、ReflectiveLoader等)-用于手动加载EXE的模板，加载时导入有效负载端
- [**18**星][2y] [Py] [ohjeongwook/srdi](https://github.com/ohjeongwook/srdi) 


***


## <a id="f7498d4f9350180b46ad63bedae4ea1b"></a>文章


- 2019.01 [fuzzysecurity] [Powershell PE Injection: This is not the Calc you are looking for!](http://fuzzysecurity.com/tutorials/20.html)
- 2018.09 [andreafortuna] [Some thoughts about PE Injection](https://www.andreafortuna.org/dfir/some-thoughts-about-pe-injection/)
- 2015.09 [n0where] [MITM PE file infector: PEInjector](https://n0where.net/mitm-pe-file-infector-peinjector)
- 2014.04 [sevagas] [PE injection explained](https://blog.sevagas.com/?PE-injection-explained)
- 2011.10 [pediy] [[原创]感染PE增加导入项实现注入](https://bbs.pediy.com/thread-141950.htm)
- 2011.04 [codereversing] [Writing a File Infector/Encrypter: PE File Modification/Section Injection (2/4)](http://www.codereversing.com/blog/archives/92)


# <a id="4df0a2fb37f3cafbdaef103e982a1b0a"></a>DLL注入


***


## <a id="4ba9c31b7264396cd7666e6b4a29b3dd"></a>集合


- [**85**星][3y] [C++] [benjaminsoelberg/reflectivepeloader](https://github.com/benjaminsoelberg/reflectivepeloader) Reflective PE loader for DLL injection


***


## <a id="f7a55b191aab1cb7a57fe44d94b54e1c"></a>工具


- [**1121**星][7y] [C] [stephenfewer/reflectivedllinjection](https://github.com/stephenfewer/reflectivedllinjection) 反射DLL注入：一种库注入技术，其中使用反射编程的概念来执行库从内存到主机进程的加载
- [**1093**星][11d] [C] [fdiskyou/injectallthethings](https://github.com/fdiskyou/injectallthethings) 实现了多个DLL注入技术的单Visual Studio项目
- [**747**星][10m] [C++] [darthton/xenos](https://github.com/darthton/xenos) Windows DLL 注入器
- [**635**星][7m] [PS] [monoxgas/srdi](https://github.com/monoxgas/srdi) Shellcode实现的反射DLL注入。将DLL转换为位置无关的Shellcode
- [**489**星][4m] [C#] [akaion/bleak](https://github.com/akaion/bleak) Windows原生DLL注入库，支持多种注入方法
- [**385**星][14d] [C++] [opensecurityresearch/dllinjector](https://github.com/opensecurityresearch/dllinjector) 实现各种方法的dll注入工具
- [**382**星][13d] [C] [wbenny/injdrv](https://github.com/wbenny/injdrv) 使用APC将DLL注入用户模式进程的Windows驱动程序
- [**277**星][2y] [C++] [gellin/teamviewer_permissions_hook_v1](https://github.com/gellin/teamviewer_permissions_hook_v1) 可注入的c++ dll，它使用裸内联连接和直接内存修改来更改您的TeamViewer权限
- [**268**星][3y] [C++] [professor-plum/reflective-driver-loader](https://github.com/professor-plum/reflective-driver-loader) 反射内核驱动注入，一种基于反射DLL注入的注入技术，绕过Windows驱动强制签名
- [**227**星][10d] [C++] [wunkolo/uwpdumper](https://github.com/wunkolo/uwpdumper) DLL和注入器，用于在运行时转储UWP应用程序，以绕过加密的文件系统保护
- [**197**星][2y] [C] [sud01oo/processinjection](https://github.com/sud01oo/ProcessInjection) 一些进程注入方法的实现及分析
- [**190**星][10d] [C++] [hzphreak/vminjector](https://github.com/hzphreak/VMInjector) 使用直接内存操作来绕过在VMware Workstation / Player上运行的主要操作系统的OS登录身份验证屏幕
- [**185**星][19d] [C++] [jonatan1024/clrinject](https://github.com/jonatan1024/clrinject) 将 C＃EXE 或 DLL 程序集注入任意CLR 运行时或者其他进程的 AppDomain
- [**178**星][1m] [Py] [infodox/python-dll-injection](https://github.com/infodox/python-dll-injection) Python工具包，用于将DLL文件注入到Windows上运行的进程中
- [**177**星][11m] [C++] [strivexjun/driverinjectdll](https://github.com/strivexjun/driverinjectdll) 使用驱动全局注入dll，可以隐藏dll模块
- [**146**星][4y] [C] [dismantl/improvedreflectivedllinjection](https://github.com/dismantl/improvedreflectivedllinjection) 原反射DLL注入技巧的升级版：使用bootstrap shell代码(x86或x64)，从反射加载器调用DLL的任何导出
- [**113**星][2m] [C] [rsmusllp/syringe](https://github.com/rsmusllp/syringe) 一个通用的DLL和代码注入工具
- [**110**星][7y] [C++] [abhisek/pe-loader-sample](https://github.com/abhisek/pe-loader-sample) 基于反射DLL注入技术的内存PE加载器
- [**87**星][2m] [C] [countercept/doublepulsar-usermode-injector](https://github.com/countercept/doublepulsar-usermode-injector) 使用 DOUBLEPULSAR payload 用户模式的 Shellcode 向其他进程注入任意 DLL
- [**86**星][3y] [C] [zerosum0x0/threadcontinue](https://github.com/zerosum0x0/threadcontinue) 使用SetThreadContext()和NtContinue()的反射DLL注入
- [**82**星][6m] [C++] [nefarius/injector](https://github.com/nefarius/injector) Command line utility to inject and eject DLLs
- [**73**星][4m] [C] [danielkrupinski/memject](https://github.com/danielkrupinski/memject) Simple Dll injector loading from memory. Supports PE header and entry point erasure. Written in C99.
- [**62**星][15d] [Py] [psychomario/pyinject](https://github.com/psychomario/pyinject) 一个python模块，帮助将shellcode/ dll注入到windows进程中
- [**61**星][3y] [C] [arvanaghi/windows-dll-injector](https://github.com/arvanaghi/windows-dll-injector) 一个基本的Windows DLL注入器在C使用CreateRemoteThread和LoadLibrary
- [**59**星][3y] [C++] [azerg/remote_dll_injector](https://github.com/azerg/remote_dll_injector) Stealth DLL injector
- [**56**星][1y] [C] [rapid7/reflectivedllinjection](https://github.com/rapid7/reflectivedllinjection) 一种库注入技术，其中使用反射编程的概念将库从内存加载到主机进程中。
- [**53**星][5m] [C] [adrianyy/keinject](https://github.com/adrianyy/keinject) Kernel LdrLoadDll injector
- [**52**星][5m] [C] [nccgroup/ncloader](https://github.com/nccgroup/ncloader) A session-0 capable dll injection utility
- [**52**星][3y] [C++] [zer0mem0ry/standardinjection](https://github.com/zer0mem0ry/standardinjection) A simple Dll Injection demonstration
- [**51**星][19d] [C++] [papadp/reflective-injection-detection](https://github.com/papadp/reflective-injection-detection) a program to detect reflective dll injection on a live machine
- [**50**星][1y] [C] [realoriginal/reflective-rewrite](https://github.com/realoriginal/reflective-rewrite) Attempt to rewrite StephenFewers Reflective DLL Injection to make it a little more stealthy. Some code taken from Meterpreter & sRDI. Currently a work in progress.
- [**49**星][3y] [C++] [zodiacon/dllinjectionwiththreadcontext](https://github.com/zodiacon/dllinjectionwiththreadcontext) This is a sample that shows how to leverage SetThreadContext for DLL injection
- [**42**星][3y] [C++] [zer0mem0ry/manualmap](https://github.com/zer0mem0ry/manualmap) A Simple demonstration of manual dll injector
- [**38**星][26d] [C++] [rolfrolles/wbdeshook](https://github.com/rolfrolles/wbdeshook) DLL-injection based solution to Brecht Wyseur's wbDES challenge (based on SysK's Phrack article)
- [**38**星][2m] [Assembly] [danielkrupinski/inflame](https://github.com/danielkrupinski/inflame) User-mode Windows DLL injector written in Assembly language (FASM syntax) with WinAPI.
- [**37**星][4m] [C++] [nanoric/pkn](https://github.com/nanoric/pkn) pkn game hacking项目核心：进程管理、内存管理和DLL注入
- [**36**星][7m] [C++] [blole/injectory](https://github.com/blole/injectory) command-line interface dll injector
- [**33**星][3m] [C++] [notscimmy/libinject](https://github.com/notscimmy/libinject) Currently supports injecting signed/unsigned DLLs in 64-bit processes
- [**31**星][4m] [Py] [fullshade/poppopret-nullbyte-dll-bypass](https://github.com/fullshade/poppopret-nullbyte-dll-bypass) 绕过一个空字节在一个popp - popp - retn地址为利用本地SEH溢出通过DLL注入的方法
- [**30**星][6m] [C++] [psmitty7373/eif](https://github.com/psmitty7373/eif) Evil Reflective DLL Injection Finder
- [**29**星][4m] [C++] [m-r-j-o-h-n/swh-injector](https://github.com/m-r-j-o-h-n/swh-injector) An Injector that can inject dll into game process protected by anti cheat using SetWindowsHookEx.
- [**29**星][4y] [C++] [stormshield/beholder-win32](https://github.com/stormshield/beholder-win32) A sample on how to inject a DLL from a kernel driver
- [**28**星][4m] [Py] [fullshade/py-memject](https://github.com/fullshade/py-memject) A Windows .DLL injector written in Python
- [**27**星][6m] [HTML] [flyrabbit/winproject](https://github.com/flyrabbit/winproject) Hook, DLLInject, PE_Tool
- [**27**星][4m] [C] [ice3man543/zeusinjector](https://github.com/ice3man543/zeusinjector) An Open Source Windows DLL Injector With All Known Techniques Available
- [**27**星][5y] [C] [olsut/kinject-x64](https://github.com/olsut/kinject-x64) Kinject - kernel dll injector, currently available in x86 version, will be updated to x64 soon.
- [**27**星][5m] [C] [sqdwr/loadimageinject](https://github.com/sqdwr/loadimageinject) LoadImage Routine Inject Dll
- [**25**星][1y] [C#] [enkomio/managedinjector](https://github.com/enkomio/managedinjector) A C# DLL injection library
- [**25**星][6y] [C] [whyallyn/paythepony](https://github.com/whyallyn/paythepony) 使用反射DLL注入库注入到远程进程，加密和要求文件的赎金，并造成我的小马疯狂的系统。
- [**24**星][2m] [C#] [tmthrgd/dll-injector](https://github.com/tmthrgd/dll-injector) Inject and detour DLLs and program functions both managed and unmanaged in other programs, written (almost) purely in C#. [Not maintained].
- [**21**星][3y] [C] [al-homedawy/injector](https://github.com/al-homedawy/injector) A Windows driver used to facilitate DLL injection
- [**21**星][5y] [C] [nyx0/dll-inj3cti0n](https://github.com/nyx0/dll-inj3cti0n) Another dll injection tool.
- [**21**星][29d] [C++] [coreyauger/slimhook](https://github.com/coreyauger/slimhook) Demonstration of dll injection. As well loading .net runtime and calling .net code. Example hijacking d3d9 dll and altering rendering of games.
- [**17**星][12m] [C] [strobejb/injdll](https://github.com/strobejb/injdll) DLL Injection commandline utility
- [**17**星][5m] [C#] [cameronaavik/ilject](https://github.com/cameronaavik/ilject) Provides a way which you can load a .NET dll/exe from disk, modify/inject IL, and then run the assembly all in memory without modifying the file.
- [**15**星][2y] [C] [ntraiseharderror/phage](https://github.com/ntraiseharderror/phage) Reflective DLL Injection style process infector
- [**15**星][3y] [C] [portcullislabs/wxpolicyenforcer](https://github.com/portcullislabs/wxpolicyenforcer) Injectable Windows DLL which enforces a W^X memory policy on a process
- [**14**星][4m] [C#] [ulysseswu/vinjex](https://github.com/ulysseswu/vinjex) A simple DLL injection lib using Easyhook, inspired by VInj.
- [**13**星][1y] [C++] [matrix86/wincodeinjection](https://github.com/matrix86/wincodeinjection) Dll Injection and Code injection sample
- [**13**星][4y] [C++] [spl0i7/dllinject](https://github.com/spl0i7/dllinject) Mineweeper bot by DLL Injection
- [**12**星][4m] [C++] [sherazibrahim/dll-injector](https://github.com/sherazibrahim/dll-injector) 一个dll注入器
- [**11**星][9m] [C#] [ihack4falafel/dll-injection](https://github.com/ihack4falafel/dll-injection) C# program that takes process id and path to DLL payload to perform DLL injection method.
- [**9**星][18d] [C++] [pfussell/pivotal](https://github.com/pfussell/pivotal) A MITM proxy server for reflective DLL injection through WinINet
- [**9**星][9m] [C] [userexistserror/injectdll](https://github.com/userexistserror/injectdll) Inject a Dll from memory
- [**9**星][1y] [Assembly] [dentrax/dll-injection-with-assembly](https://github.com/dentrax/dll-injection-with-assembly) DLL Injection to Exe with Assembly using OllyDbg
- [**7**星][1y] [C] [haidragon/newinjectdrv](https://github.com/haidragon/newinjectdrv) APC注入DLL内核层
- [**6**星][2y] [thesph1nx/covenant](https://github.com/thesph1nx/covenant) Metepreter clone - DLL Injection Backdoor
- [**5**星][5y] [C++] [ciantic/remotethreader](https://github.com/ciantic/remotethreader) Helps you to inject your dll in another process
- [**5**星][4m] [C++] [reclassnet/reclass.net-memorypipeplugin](https://github.com/reclassnet/reclass.net-memorypipeplugin) A ReClass.NET plugin which allows direct memory access via dll injection.
- [**1**星][1y] [PS] [getrektboy724/maldll](https://github.com/getrektboy724/maldll) A bunch of malicius dll to inject to a process


***


## <a id="f69bdae6414fe41f7b2ff0a5ae646e0e"></a>文章


- 2020.02 [0x00sec] [DLL injections (safety)](https://0x00sec.org/t/dll-injections-safety/19496)
- 2019.08 [tyranidslair] [Windows Code Injection: Bypassing CIG Through KnownDlls](https://www.tiraniddo.dev/2019/08/windows-code-injection-bypassing-cig.html)
- 2019.08 [tyranidslair] [Windows Code Injection: Bypassing CIG Through KnownDlls](https://tyranidslair.blogspot.com/2019/08/windows-code-injection-bypassing-cig.html)
- 2019.03 [code610] [DLL Injection - part 2](https://code610.blogspot.com/2019/03/dll-injection-part-2.html)
- 2018.10 [pediy] [[原创]代替创建用户线程使用ShellCode注入DLL的小技巧](https://bbs.pediy.com/thread-247515.htm)
- 2018.10 [4hou] [如何利用DLL注入绕过Win10勒索软件保护](http://www.4hou.com/technology/13923.html)
- 2018.10 [0x00sec] [Reflective Dll Injection - Any Way to check If a process is already injected?](https://0x00sec.org/t/reflective-dll-injection-any-way-to-check-if-a-process-is-already-injected/8980/)
- 2018.09 [pediy] [[原创]win10_arm64 驱动注入dll 到 arm32程序](https://bbs.pediy.com/thread-247032.htm)
- 2018.09 [code610] [DLL Injection - part 1](https://code610.blogspot.com/2018/09/dll-injection-part-1.html)
- 2018.08 [freebuf] [sRDI：一款通过Shellcode实现反射型DLL注入的强大工具](http://www.freebuf.com/sectool/181426.html)
- 2018.08 [vkremez] [Let's Learn: Dissecting Panda Banker & Modules: Webinject, Grabber & Keylogger DLL Modules](https://www.vkremez.com/2018/08/lets-learn-dissecting-panda-banker.html)
- 2018.07 [4hou] [注入系列——DLL注入](http://www.4hou.com/technology/12703.html)
- 2018.06 [0x00sec] [Reflective DLL Injection - AV detects at runtime](https://0x00sec.org/t/reflective-dll-injection-av-detects-at-runtime/7307/)
- 2018.06 [qq] [【游戏漏洞】注入DLL显示游戏窗口](http://gslab.qq.com/article-508-1.html)
- 2018.06 [pediy] [[原创]远程注入之dll模块深度隐藏](https://bbs.pediy.com/thread-228710.htm)
- 2018.02 [pediy] [[求助]内存dll的远程线程注入，如何使用MemoryModule开源库？](https://bbs.pediy.com/thread-224489.htm)
- 2017.12 [secist] [Mavinject | Dll Injected](http://www.secist.com/archives/5912.html)
- 2017.12 [secvul] [SSM终结dll注入](https://secvul.com/topics/951.html)
- 2017.10 [nsfocus] [【干货分享】Sandbox技术之DLL注入](http://blog.nsfocus.net/sandbox-technology-dll-injection/)
- 2017.10 [freebuf] [DLL注入新姿势：反射式DLL注入研究](http://www.freebuf.com/articles/system/151161.html)
- 2017.10 [pediy] [[原创]通过Wannacry分析内核shellcode注入dll技术](https://bbs.pediy.com/thread-221756.htm)
- 2017.09 [360] [利用DLL延迟加载实现远程代码注入](https://www.anquanke.com/post/id/86919/)
- 2017.09 [360] [Dll注入新姿势：SetThreadContext注入](https://www.anquanke.com/post/id/86786/)
- 2017.08 [silentbreaksecurity] [sRDI – Shellcode Reflective DLL Injection](https://silentbreaksecurity.com/srdi-shellcode-reflective-dll-injection/)
- 2017.08 [360] [DLL注入那些事](https://www.anquanke.com/post/id/86671/)
- 2017.08 [freebuf] [系统安全攻防战：DLL注入技术详解](http://www.freebuf.com/articles/system/143640.html)
- 2017.08 [pediy] [[翻译]多种DLL注入技术原理介绍](https://bbs.pediy.com/thread-220405.htm)
- 2017.07 [0x00sec] [Reflective DLL Injection](https://0x00sec.org/t/reflective-dll-injection/3080/)
- 2017.07 [zerosum0x0] [利用 SetThreadContext() 和 NtContinue() 实现反射 DLL 加载](https://zerosum0x0.blogspot.com/2017/07/threadcontinue-reflective-injection.html)
- 2017.07 [zerosum0x0] [Proposed Windows 10 EAF/EMET "Bypass" for Reflective DLL Injection](https://zerosum0x0.blogspot.com/2017/06/proposed-eafemet-bypass-for-reflective.html)
- 2017.05 [360] [NSA武器库：DOUBLEPULSAR的内核DLL注入技术](https://www.anquanke.com/post/id/86137/)
- 2017.05 [lallouslab] [7 DLL injection techniques in Microsoft Windows](http://lallouslab.net/2017/05/15/7-dll-injection-techniques-in-the-microsoft-windows/)
- 2017.05 [3or] [mimilib DHCP Server Callout DLL injection](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)
- 2017.05 [3or] [Hunting DNS Server Level Plugin dll injection](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html)
- 2017.04 [arvanaghi] [DLL Injection Using LoadLibrary in C](https://arvanaghi.com/blog/dll-injection-using-loadlibrary-in-C/)
- 2017.04 [4hou] [通过APC实现Dll注入——绕过Sysmon监控](http://www.4hou.com/technology/4393.html)
- 2017.04 [bogner] [CVE-2017-3511: Code Injection through DLL Sideloading in 64bit Oracle Java](https://bogner.sh/2017/04/cve-2017-3511-code-injection-through-dll-sideloading-in-64bit-oracle-java/)
- 2017.04 [countercept] [Analyzing the DOUBLEPULSAR Kernel DLL Injection Technique](https://countercept.com/blog/analyzing-the-doublepulsar-kernel-dll-injection-technique/)
- 2017.04 [countercept] [NSA武器库：DOUBLEPULSAR的内核DLL注入技术](https://countercept.com/our-thinking/analyzing-the-doublepulsar-kernel-dll-injection-technique/)
- 2017.04 [3gstudent] [通过APC实现Dll注入——绕过Sysmon监控](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87APC%E5%AE%9E%E7%8E%B0Dll%E6%B3%A8%E5%85%A5-%E7%BB%95%E8%BF%87Sysmon%E7%9B%91%E6%8E%A7/)
- 2017.04 [pentestlab] [DLL Injection](https://pentestlab.blog/2017/04/04/dll-injection/)
- 2017.03 [pediy] [[原创]不用导出任何函数的DLL劫持注入,完美!](https://bbs.pediy.com/thread-216348.htm)
- 2016.06 [lowleveldesign] [!injectdll – a remote thread approach](https://lowleveldesign.org/2016/06/27/injectdll-a-remote-thread-approach/)
- 2016.06 [lowleveldesign] [!injectdll – a WinDbg extension for DLL injection](https://lowleveldesign.org/2016/06/22/injectdll-a-windbg-extension-for-dll-injection/)
- 2016.04 [ketansingh] [Hacking games with DLL Injection](https://ketansingh.net/hacking-games-with-dll-injection/)
- 2016.02 [freebuf] [通过 DLL 注入和代码修改绕过 XIGNCODE3 的反作弊保护](http://www.freebuf.com/articles/terminal/96741.html)
- 2016.01 [freebuf] [DLL注入的几种姿势（二）：CreateRemoteThread And More](http://www.freebuf.com/articles/system/94693.html)
- 2016.01 [freebuf] [DLL注入的几种姿势（一）：Windows Hooks](http://www.freebuf.com/articles/system/93413.html)
- 2015.11 [modexp] [DLL/PIC Injection on Windows from Wow64 process](https://modexp.wordpress.com/2015/11/19/dllpic-injection-on-windows-from-wow64-process/)
- 2015.09 [pediy] [[原创]c++ 载入内存中dll ,以及内存注入 (已开源)](https://bbs.pediy.com/thread-203894.htm)
- 2015.08 [rapid7] [Using Reflective DLL Injection to exploit IE Elevation Policies](https://blog.rapid7.com/2015/08/28/using-reflective-dll-injection-to-exploit-ie-elevation-policies/)
- 2015.07 [pediy] [[原创]今天写了个apc注入dll代码，可以当工具使用](https://bbs.pediy.com/thread-202078.htm)
- 2015.05 [codereversing] [Debugging Injected DLLs](http://www.codereversing.com/blog/archives/219)
- 2015.05 [WarrantyVoider] [DAI dll injection test - successfull](https://www.youtube.com/watch?v=hYU_W1gRtZE)
- 2015.04 [securestate] [DLL Injection Part 2: CreateRemoteThread and More](https://warroom.securestate.com/dll-injection-part-2-createremotethread-and-more/)
- 2015.03 [securestate] [DLL Injection Part 1: SetWindowsHookEx](https://warroom.rsmus.com/dll-injection-part-1-setwindowshookex/)
- 2015.03 [securestate] [DLL Injection Part 0: Understanding DLL Usage](https://warroom.rsmus.com/dll-injection-part-0-understanding-dll-usage/)
- 2014.10 [codingvision] [C# Inject a Dll into a Process (w/ CreateRemoteThread)](http://codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread)
- 2014.04 [pediy] [[分享]重读老文章：DLL注入的又一个梗](https://bbs.pediy.com/thread-186778.htm)
- 2014.04 [pediy] [[分享]老文章系列：APC注入DLL的梗](https://bbs.pediy.com/thread-186631.htm)
- 2014.03 [trustwave] [Old School Code Injection in an ATM .dll](https://www.trustwave.com/Resources/SpiderLabs-Blog/Old-School-Code-Injection-in-an-ATM--dll/)
- 2014.01 [osandamalith] [Ophcrack Path Subversion Arbitrary DLL Injection Code Execution](https://osandamalith.com/2014/01/18/ophcrack-path-subversion-arbitrary-dll-injection-code-execution/)
- 2013.12 [pediy] [[原创]DLL自卸载无模块注入源码(一)](https://bbs.pediy.com/thread-182069.htm)
- 2013.09 [debasish] [Inline API Hooking using DLL Injection](http://www.debasish.in/2013/09/inline-api-hooking-using-dll-injection.html)
- 2013.09 [freebuf] [对国内各种安全卫士产品的一种通用虐杀、DLL注入、本地代码执行的方法](http://www.freebuf.com/vuls/12597.html)
- 2013.08 [pediy] [[原创]重温远程注入-------无dll](https://bbs.pediy.com/thread-176702.htm)
- 2013.06 [msreverseengineering] [What is DLL Injection and How is it used for Reverse Engineering?](http://www.msreverseengineering.com/blog/2014/6/23/what-is-dll-injection-and-how-is-it-used-for-reverse-engineering)
- 2013.05 [pediy] [[原创]关于dll注入方法](https://bbs.pediy.com/thread-171190.htm)
- 2013.03 [pediy] [[原创]DLL注入之远线程方式](https://bbs.pediy.com/thread-167175.htm)
- 2013.02 [pediy] [[原创]易语言静态编译的DLL注入到其他语言写的EXE中后的完美卸载](https://bbs.pediy.com/thread-162742.htm)
- 2012.10 [octopuslabs] [DLL Injection – A Splash Bitmap](http://octopuslabs.io/legend/blog/archives/1785)
- 2012.09 [debasish] [KeyLogging through DLL Injection[The Simplest Way]](http://www.debasish.in/2012/09/keylogging-through-dll-injectionthe.html)
- 2012.09 [volatility] [MoVP 2.1 Atoms (The New Mutex), Classes and DLL Injection](https://volatility-labs.blogspot.com/2012/09/movp-21-atoms-new-mutex-classes-and-dll.html)
- 2012.06 [freebuf] [[更新]一款非常不错的dll注入器 – RemoteDLL V2](http://www.freebuf.com/sectool/3970.html)
- 2012.05 [brindi] [DLL and Code Injection in Python](http://brindi.si/g/blog/dll-and-code-injection-in-python.html)
- 2011.11 [pediy] [[原创]滴水逆向学习收获1-双进程无dll注入（1楼，17楼，21楼，27楼，30楼，33楼）[已更新至33楼]](https://bbs.pediy.com/thread-142554.htm)
- 2011.06 [pediy] [[原创]利用钩子函数来注入DLL的一个具体应用：点击桌面不同图标，播放相应音符](https://bbs.pediy.com/thread-136144.htm)
- 2011.01 [pediy] [[原创]进程管理dll注入综合小工具[附源码]](https://bbs.pediy.com/thread-127924.htm)
- 2010.12 [pediy] [[原创]Ring3下劫持CreateProcess注入dll](https://bbs.pediy.com/thread-126226.htm)
- 2010.01 [pediy] [[原创]dll注入辅助工具[带源码]](https://bbs.pediy.com/thread-104642.htm)
- 2009.08 [pediy] [[原创]最简单的DLL注入](https://bbs.pediy.com/thread-94799.htm)
- 2009.07 [pediy] [[原创]注入DLL之ANSI版--改自Jeffrey的《windows核心编程》](https://bbs.pediy.com/thread-92631.htm)
- 2009.04 [pediy] [不需要依赖dllmain触发的CE注入代码](https://bbs.pediy.com/thread-85899.htm)
- 2008.12 [pediy] [[原创][代程]远程线程详解(一):无DLL远程线程注入](https://bbs.pediy.com/thread-78032.htm)
- 2008.11 [sans] [Finding stealth injected DLLs](https://isc.sans.edu/forums/diary/Finding+stealth+injected+DLLs/5356/)
- 2008.11 [pediy] [[原创]N种内核注入DLL的思路及实现](https://bbs.pediy.com/thread-75887.htm)
- 2008.10 [pediy] [[原创]IAT HOOK 代码注入非DLL](https://bbs.pediy.com/thread-74569.htm)
- 2008.03 [pediy] [[献丑]Win32汇编实现DLL的远程注入及卸载](https://bbs.pediy.com/thread-60763.htm)
- 2007.12 [pediy] [[原创]QueueUserApc实现DLL注入](https://bbs.pediy.com/thread-56071.htm)
- 2006.11 [pediy] [再谈Dll注入NetTransport 2.25.337[原创]](https://bbs.pediy.com/thread-35556.htm)
- 2006.10 [pediy] [[原创]Dll注入NetTransport 2.25.337](https://bbs.pediy.com/thread-34096.htm)
- 2005.08 [pediy] [ApiHook，InjectDll 单元及其应用 [Delphi代码]](https://bbs.pediy.com/thread-16088.htm)


# <a id="97ceb80739f1d2efce08baaf98dce0fc"></a>进程注入


***


## <a id="5ed3d284b106ffdc141f447f59326b00"></a>工具


- [**2389**星][10d] [Py] [lmacken/pyrasite](https://github.com/lmacken/pyrasite) 向运行中的 Python进程注入代码
- [**1568**星][17d] [Py] [google/pyringe](https://github.com/google/pyringe) Python调试器，可附加Python进程并向其中注入代码
- [**1486**星][3m] [C] [rikkaapps/riru](https://github.com/rikkaapps/riru) 通过替换libmemtrack注入合子进程
- [**899**星][1y] [C++] [secrary/injectproc](https://github.com/secrary/injectproc) 多种DLL注入、进程替换、Hook注入、APC注入的实现
- [**655**星][4y] [C] [rentzsch/mach_inject](https://github.com/rentzsch/mach_inject) Mac OS X的进程间代码注入
- [**589**星][14d] [C] [gaffe23/linux-inject](https://github.com/gaffe23/linux-inject) Tool for injecting a shared object into a Linux process
- [**536**星][13d] [C] [odzhan/injection](https://github.com/odzhan/injection) Windows process injection methods
- [**435**星][11d] [Py] [davidbuchanan314/dlinject](https://github.com/davidbuchanan314/dlinject) Inject a shared library (i.e. arbitrary code) into a live linux process, without ptrace
- [**413**星][4y] [C#] [zenlulz/memorysharp](https://github.com/zenlulz/memorysharp) Windows程序内存编辑库，C#编写，可向远程进程注入输入和代码，或读取远程进程内存
- [**381**星][14d] [C++] [evilsocket/arminject](https://github.com/evilsocket/arminject) An application to dynamically inject a shared object into a running process on ARM architectures.
- [**376**星][12d] [C++] [theevilbit/injection](https://github.com/theevilbit/injection) various process injection technique
- [**363**星][4m] [C++] [safebreach-labs/pinjectra](https://github.com/safebreach-labs/pinjectra) 一个实现进程注入技术的类C/ c++类操作系统库(主要关注Windows 10 64位)
- [**362**星][4m] [C#] [rasta-mouse/tikitorch](https://github.com/rasta-mouse/tikitorch) Process Injection
- [**294**星][26d] [C] [quarkslab/quarkspwdump](https://github.com/quarkslab/quarkspwdump) Dump various types of Windows credentials without injecting in any process.
- [**267**星][2y] [C++] [chadski/sharpneedle](https://github.com/chadski/sharpneedle) Inject C# code into a running process
- [**246**星][16d] [C] [suvllian/process-inject](https://github.com/suvllian/process-inject) 在Windows环境下的进程注入方法：远程线程注入、创建进程挂起注入、反射注入、APCInject、SetWindowHookEX注入
- [**204**星][4y] [C] [dismantl/linux-injector](https://github.com/dismantl/linux-injector) Utility for injecting executable code into a running process on x86/x64 Linux
- [**163**星][1m] [C] [dhavalkapil/libdheap](https://github.com/dhavalkapil/libdheap) 可以透明地注入到不同进程的共享(动态)库，以检测glibc堆中的内存损坏
- [**157**星][9m] [C] [hasherezade/process_doppelganging](https://github.com/hasherezade/process_doppelganging) 进程注入技术 Process Doppelganging 的实现代码
- [**154**星][1m] [C] [ixty/mandibule](https://github.com/ixty/mandibule) 向远程进程注入ELF文件
- [**144**星][4m] [PS] [empireproject/psinject](https://github.com/empireproject/psinject) Inject PowerShell into any process
- [**142**星][4m] [C#] [3xpl01tc0d3r/processinjection](https://github.com/3xpl01tc0d3r/processinjection) This program is designed to demonstrate various process injection techniques
- [**142**星][4m] [C] [antoniococo/mapping-injection](https://github.com/antoniococo/mapping-injection) Just another Windows Process Injection
- [**126**星][8d] [C++] [ez8-co/yapi](https://github.com/ez8-co/yapi) fusion injector that reduce differences between x64, wow64 and x86 processes
- [**111**星][5m] [C++] [arno0x/tcprelayinjecter](https://github.com/arno0x/tcprelayinjecter) Tool for injecting a "TCP Relay" managed assembly into unmanaged processes
- [**110**星][16d] [Shell] [aoncyberlabs/cexigua](https://github.com/AonCyberLabs/Cexigua) Linux based inter-process code injection without ptrace(2)
- [**85**星][1m] [C] [elfmaster/saruman](https://github.com/elfmaster/saruman) ELF anti-forensics exec, for injecting full dynamic executables into process image (With thread injection)
- [**76**星][5y] [C++] [malwaretech/zombifyprocess](https://github.com/malwaretech/zombifyprocess) Inject code into a legitimate process
- [**62**星][8m] [C] [kubo/injector](https://github.com/kubo/injector) Library for injecting a shared library into a Linux or Windows process
- [**59**星][4y] [C] [infosecguerrilla/reflectivesoinjection](https://github.com/infosecguerrilla/reflectivesoinjection) 一种库注入技术，其中使用反射编程的概念将库从内存加载到主机进程中
- [**53**星][1m] [Py] [xiphosresearch/steelcon-python-injection](https://github.com/xiphosresearch/steelcon-python-injection) Python Process Injection PoC Code from my SteelCon talk in 2014
- [**52**星][6y] [C++] [georgenicolaou/heaveninjector](https://github.com/georgenicolaou/heaveninjector) Simple proof of concept code for injecting libraries on 64bit processes from a 32bit process
- [**47**星][7m] [PS] [3gstudent/code-execution-and-process-injection](https://github.com/3gstudent/code-execution-and-process-injection) Powershell to CodeExecution and ProcessInjection
- [**46**星][5y] [C++] [tandasat/remotewritemonitor](https://github.com/tandasat/remotewritemonitor) A tool to help malware analysts tell that the sample is injecting code into other process.
- [**37**星][4m] [C] [egguncle/ptraceinject](https://github.com/egguncle/ptraceinject) 进程注入
- [**31**星][25d] [ObjC] [cwbudde/cordova-plugin-wkwebview-inject-cookie](https://github.com/cwbudde/cordova-plugin-wkwebview-inject-cookie) Injects a cookie in order to start the sync processs with wkWebView
- [**30**星][2y] [C++] [ntraiseharderror/unrunpe](https://github.com/ntraiseharderror/unrunpe) PoC for detecting and dumping process hollowing code injection
- [**30**星][4m] [C#] [mr-un1k0d3r/remoteprocessinjection](https://github.com/mr-un1k0d3r/remoteprocessinjection) C# remote process injection utility for Cobalt Strike
- [**16**星][2y] [C++] [xfgryujk/injectexe](https://github.com/xfgryujk/injectexe) Inject the whole exe into another process
- [**16**星][1m] [C] [narhen/procjack](https://github.com/narhen/procjack) PoC of injecting code into a running Linux process
- [**14**星][24d] [C++] [eternityx/zinjector](https://github.com/eternityx/zinjector) zInjector is a simple tool for injecting dynamic link libraries into arbitrary processes
- [**10**星][2m] [JS] [lmangani/node_ssl_logger](https://github.com/lmangani/node_ssl_logger) Decrypt and log process SSL traffic via Frida Injection
- [**10**星][1y] [C++] [shaxzy/vibranceinjector](https://github.com/shaxzy/vibranceinjector) Mono process injector
- [**8**星][5y] [C++] [hkhk366/memory_codes_injection](https://github.com/hkhk366/memory_codes_injection) 将代码注入到另一个进程中，以监视和操作其他进程。这通常被用作杀毒软件
- [**6**星][2m] [ObjC] [couleeapps/mach_inject_32](https://github.com/couleeapps/mach_inject_32) Inject libraries into 32 processes on macOS Mojave
- [**6**星][3m] [Jupyter Notebook] [jsecurity101/detecting-process-injection-techniques](https://github.com/jsecurity101/detecting-process-injection-techniques) This is a repository that is meant to hold detections for various process injection techniques.
- [**1**星][2y] [C++] [malwaresec/processinjection](https://github.com/malwaresec/processinjection) Repo for process injection source files
- [**None**星][C] [realoriginal/ppdump-public](https://github.com/realoriginal/ppdump-public) 使用Zemana AntiMalware引擎打开一个特权句柄到一个PP/PPL进程并注入MiniDumpWriteDump()


***


## <a id="78df9ff3771ac1e9d9dff3eba0055d25"></a>文章


- 2020.04 [infosecinstitute] [MITRE ATT&CK spotlight: Process injection](https://resources.infosecinstitute.com/mitre-attck-spotlight-process-injection/)
- 2020.03 [jsecurity101] [Engineering Process Injection Detections -](https://posts.specterops.io/engineering-process-injection-detections-part-1-research-951e96ad3c85)
- 2020.02 [vkremez] [Let's Learn: Inside Parallax RAT Malware: Process Hollowing Injection & Process Doppelgänging API Mix: Part I](https://www.vkremez.com/2020/02/lets-learn-inside-parallax-rat-malware.html)
- 2020.01 [BlackHat] [Process Injection Techniques - Gotta Catch Them All](https://www.youtube.com/watch?v=xewv122qxnk)
- 2020.01 [hakin9] [Mapping-Injection: Just another Windows Process Injection](https://hakin9.org/mapping-injection-just-another-windows-process-injection/)
- 2019.12 [HackersOnBoard] [DEF CON 27 - Itzik Kotler - Process Injection Techniques Gotta Catch Them All](https://www.youtube.com/watch?v=KSDR06TO_9o)
- 2019.11 [freebuf] [ATT&CK中的进程注入三部曲](https://www.freebuf.com/articles/web/218232.html)
- 2019.11 [4hou] [实现Windows进程注入的7种新方法](https://www.4hou.com/system/17735.html)
- 2019.10 [Cooper] [Fileless Malware Infection And Linux Process Injection In Linux OS - Hendrik Adrian](https://www.youtube.com/watch?v=RvBj8C5okp0)
- 2019.09 [freebuf] [在遇到shellcode注入进程时所使用的调试技](https://www.freebuf.com/articles/system/212248.html)
- 2019.09 [aliyun] [细说Cobalt Strike进程注入](https://xz.aliyun.com/t/6205)
- 2019.09 [aliyun] [进程注入概述（一）](https://xz.aliyun.com/t/6210)
- 2019.09 [sevagas] [Process PE Injection Basics](https://blog.sevagas.com/?Process-PE-Injection-Basics)
- 2019.08 [4hou] [远程进程shellcode注入调试技巧](https://www.4hou.com/system/19852.html)
- 2019.08 [cobaltstrike] [Cobalt Strike’s Process Injection: The Details](https://blog.cobaltstrike.com/2019/08/21/cobalt-strikes-process-injection-the-details/)
- 2019.07 [fortinet] [A Deep Dive Into IcedID Malware: Part I - Unpacking, Hooking and Process Injection](https://www.fortinet.com/blog/threat-research/icedid-malware-analysis-part-one.html)
- 2019.05 [4hou] [借助ProcessHollowing和代码注入感染合法进程：信息窃取恶意软件FormBook分析](https://www.4hou.com/technology/17823.html)
- 2019.04 [OALabs] [Reverse Engineering Quick Tip - Unpacking Process Injection With a Single Breakpoint](https://www.youtube.com/watch?v=Min6DWTHDBw)
- 2018.12 [4hou] [如何借助COM对Windows受保护进程进行代码注入（第二部分）](http://www.4hou.com/system/14904.html)
- 2018.11 [googleprojectzero] [利用COM向Windows受保护进程注入代码, Part2](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)
- 2018.11 [andreafortuna] [Process Injection and Persistence using Application Shimming](https://www.andreafortuna.org/dfir/malware-analysis/process-injection-and-persistence-using-application-shimming/)
- 2018.11 [4hou] [如何借助COM对Windows受保护进程进行代码注入](http://www.4hou.com/system/14133.html)
- 2018.10 [freebuf] [十种进程注入技术介绍：常见注入技术及趋势调查](https://www.freebuf.com/articles/system/187239.html)
- 2018.10 [360] [如何将.NET程序注入到非托管进程](https://www.anquanke.com/post/id/162914/)
- 2018.10 [aliyun] [使用COM将代码注入到受Windows保护的进程中](https://xz.aliyun.com/t/3070)
- 2018.10 [aliyun] [【老文】如何将.Net程序集注入非托管进程](https://xz.aliyun.com/t/3050)
- 2018.10 [googleprojectzero] [Injecting Code into Windows Protected Processes using COM - Part 1](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html)
- 2018.10 [4hou] [如何针对Windows中ConsoleWindowClass对象实现进程注入](http://www.4hou.com/technology/13634.html)
- 2018.09 [aliyun] [windows 进程注入之控制台窗口类](https://xz.aliyun.com/t/2762)
- 2018.08 [4hou] [Windows进程注入：额外的窗口字节](http://www.4hou.com/system/13308.html)
- 2018.08 [aliyun] [Windows进程注入技术之额外的Window字节篇](https://xz.aliyun.com/t/2656)
- 2018.08 [aliyun] [Windows进程注入技术之PROPagate篇](https://xz.aliyun.com/t/2639)
- 2018.07 [malcomvetter] [.NET Process Injection](https://medium.com/p/1a1af00359bc)
- 2018.07 [4hou] [攻击者如何向正在运行的Linux进程注入恶意代码](http://www.4hou.com/technology/12736.html)
- 2018.07 [4hou] [Windows进程注入：如何将有效负载部署到目标进程的内存空间中执行](http://www.4hou.com/technology/12672.html)
- 2018.07 [360] [Windows进程注入payload分析](https://www.anquanke.com/post/id/151840/)
- 2018.05 [freebuf] [利用“进程注入”实现无文件复活 WebShell](http://www.freebuf.com/articles/web/172753.html)
- 2018.05 [4hou] [CTRL-INJECT进程注入技术详解](http://www.4hou.com/technology/11636.html)
- 2018.05 [360] [针对新型进程注入技术Ctrl-Inject的原理分析](https://www.anquanke.com/post/id/129769/)
- 2018.04 [360] [深入分析Get-InjectedThread进程注入检测工具的原理并尝试绕过](https://www.anquanke.com/post/id/104339/)
- 2018.04 [360] [深入分析恶意软件Formbook：混淆和进程注入（下）](https://www.anquanke.com/post/id/103429/)
- 2018.04 [360] [深入分析恶意软件Formbook：混淆和进程注入（上）](https://www.anquanke.com/post/id/103403/)
- 2018.03 [aliyun] [利用GDB实现进程注入](https://xz.aliyun.com/t/2164)
- 2018.02 [endgame] [Stopping Olympic Destroyer: New Process Injection Insights](https://www.endgame.com/blog/technical-blog/stopping-olympic-destroyer-new-process-injection-insights)
- 2018.01 [4hou] [恶意软件Ursnif的隐蔽进程注入技术分析](http://www.4hou.com/info/news/9902.html)
- 2018.01 [vkremez] [Let's Learn: Dissect Panda Banking Malware's "libinject" Process Injection Module](https://www.vkremez.com/2018/01/lets-learn-dissect-panda-banking.html)
- 2017.12 [4hou] [Ursnif恶意软件变种技术新升级，利用TLS回调技术进程注入](http://www.4hou.com/system/8988.html)
- 2017.11 [fireeye] [Ursnif 变种使用 TLS 回调技巧实现进程注入](https://www.fireeye.com/blog/threat-research/2017/11/ursnif-variant-malicious-tls-callback-technique.html)
- 2017.11 [freebuf] [使用恶意软件将隐藏代码注入已知进程的渗透研究](http://www.freebuf.com/articles/system/153795.html)
- 2017.11 [OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 2)](https://www.youtube.com/watch?v=kdNQhfgoQoU)
- 2017.11 [OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 1)](https://www.youtube.com/watch?v=ScBB-Hi7NxQ)
- 2017.10 [securityintelligence] [Diving Into Zberp’s Unconventional Process Injection Technique](https://securityintelligence.com/diving-into-zberps-unconventional-process-injection-technique/)
- 2017.09 [4hou] [无需Ptrace就能实现Linux进程间代码注入](http://www.4hou.com/technology/7614.html)
- 2017.09 [gdssecurity] [Linux 进程内代码注入（无需Ptrace）](https://blog.gdssecurity.com/labs/2017/9/5/linux-based-inter-process-code-injection-without-ptrace2.html)
- 2017.08 [pediy] [[翻译]十种注入技巧:具有通用性的进程注入技巧研究](https://bbs.pediy.com/thread-220500.htm)
- 2017.07 [4hou] [十种流行进程注入技术详细分析](http://www.4hou.com/technology/6735.html)
- 2017.07 [360] [10种常见的进程注入技术的总结](https://www.anquanke.com/post/id/86463/)
- 2017.07 [endgame] [10种进程注入技术：普通和流行的进程注入技术调查](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- 2017.07 [vulnerablelife] [Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques](https://vulnerablelife.wordpress.com/2017/07/18/ten-process-injection-techniques-a-technical-survey-of-common-and-trending-process-injection-techniques/)
- 2017.07 [microsoft] [Detecting stealthier cross-process injection techniques with Windows Defender ATP: Process hollowing and atom bombing](https://cloudblogs.microsoft.com/microsoftsecure/2017/07/12/detecting-stealthier-cross-process-injection-techniques-with-windows-defender-atp-process-hollowing-and-atom-bombing/)
- 2017.07 [struppigel] [Process Injection Info Graphic](https://struppigel.blogspot.com/2017/07/process-injection-info-graphic.html)
- 2017.07 [freebuf] [pyrasite – 向python进程注入代码工具](http://www.freebuf.com/sectool/139120.html)
- 2017.05 [MalwareAnalysisForHedgehogs] [Malware Analysis - Code Injection via CreateRemoteThread & WriteProcessMemory](https://www.youtube.com/watch?v=W_rAxPm4TTU)
- 2017.04 [4hou] [在Linux下使用ptrace向sshd进程注入任意代码](http://www.4hou.com/technology/4446.html)
- 2017.03 [360] [DoubleAgent：代码注入和持久化技术--允许在任何Windows版本上控制任何进程](https://www.anquanke.com/post/id/85775/)
- 2017.03 [] [DoubleAgent技术：任意进程下代码注入与权限维持](http://0day5.com/archives/4364/)
- 2017.03 [microsoft] [Uncovering cross-process injection with Windows Defender ATP](https://cloudblogs.microsoft.com/microsoftsecure/2017/03/08/uncovering-cross-process-injection-with-windows-defender-atp/)
- 2017.02 [4hou] [32位程序对64位进程的远程注入实现](http://www.4hou.com/technology/3426.html)
- 2016.02 [360] [linux-inject：注入代码到运行的Linux进程中](https://www.anquanke.com/post/id/83423/)
- 2015.08 [pediy] [[原创]win7 32位进程注入64位进程](https://bbs.pediy.com/thread-203762.htm)
- 2015.08 [christophertruncer] [Injecting Shellcode into a Remote Process with Python](https://www.christophertruncer.com/injecting-shellcode-into-a-remote-process-with-python/)
- 2015.08 [pediy] [[原创]纯C++编写Win32/X64通用Shellcode注入csrss进程.](https://bbs.pediy.com/thread-203140.htm)
- 2015.08 [securestate] [Injecting Python Code Into Native Processes](https://warroom.securestate.com/injecting-python-code-into-native-processes/)
- 2015.08 [securestate] [Injecting Python Code Into Native Processes](https://warroom.rsmus.com/injecting-python-code-into-native-processes/)
- 2015.05 [redcanary] [What Red Canary Detects: Spotlight on Process Injection](https://redcanary.com/blog/what-red-canary-detects-process-injection/)
- 2015.04 [pediy] [[原创]一个Win7X64内核注入32位进程的例子](https://bbs.pediy.com/thread-200027.htm)
- 2014.07 [pediy] [[原创]C++进程注入（通过远程线程注入进程）](https://bbs.pediy.com/thread-190291.htm)
- 2014.06 [lastline] [Dissecting Payload Injection Using LLama Process Snapshots](https://www.lastline.com/labsblog/dissecting-payload-injection-using-llama-process-snapshots/)
- 2014.05 [talosintelligence] [Betabot Process Injection](https://blog.talosintelligence.com/2014/05/betabot-process-injection.html)
- 2014.03 [pediy] [[原创]注入安卓进程,并hook java世界的方法](https://bbs.pediy.com/thread-186054.htm)
- 2013.05 [lhj0711010212] [使用injectso技术注入mtrace，对进程进行内存检测](https://blog.csdn.net/lhj0711010212/article/details/8999413)
- 2013.04 [pediy] [[原创]另类注入 傀儡进程测试](https://bbs.pediy.com/thread-170530.htm)
- 2013.03 [pediy] [[原创]<<游戏外挂攻防艺术>>注入2.3节依赖可信进程注入](https://bbs.pediy.com/thread-163701.htm)
- 2013.01 [pediy] [[原创]多种注入进程](https://bbs.pediy.com/thread-161250.htm)
- 2012.04 [dreamofareverseengineer] [Identifying malicious injected code in Legit Process through dynamic analysis:](http://dreamofareverseengineer.blogspot.com/2012/04/identifying-malicious-injected-code-in.html)
- 2011.07 [firebitsbr] [Syringe utility provides ability to inject shellcode into processes](https://firebitsbr.wordpress.com/2011/07/08/syringe-utility-provides-ability-to-inject-shellcode-into-processes/)
- 2010.10 [pediy] [[原创]劫持正在运行进程的EIP注入代码的方法](https://bbs.pediy.com/thread-122890.htm)
- 2010.08 [pediy] [[原创]创建远程线程，将代码注入到其它进程中执行](https://bbs.pediy.com/thread-119091.htm)
- 2010.08 [console] [Bypassing AntiVirus With Process Injection](http://console-cowboys.blogspot.com/2010/08/bypassing-antivirus-with-process.html)
- 2007.12 [pediy] [[原创]进程注入——一个同时支持Win98, WinMe, Win2000, WinXp 的方法(源代码加详细注释)](https://bbs.pediy.com/thread-56751.htm)
- 2007.04 [pediy] [[原创]三线程..进程保护@远线程直接代码注入 for Delphi](https://bbs.pediy.com/thread-42594.htm)
- 2004.06 [pediy] [用进程注入来实现一个壳](https://bbs.pediy.com/thread-1564.htm)


# <a id="3b2252d379d384475de4654bd5d0b368"></a>线程注入


***


## <a id="9ff33dd10584407a654590a7cf18c6f0"></a>工具


- [**49**星][2y] [C] [vallejocc/poc-inject-data-wm_copydata](https://github.com/vallejocc/poc-inject-data-wm_copydata) A tiny PoC to inject and execute code into explorer.exe with WM_SETTEXT+WM_COPYDATA+SetThreadContext


***


## <a id="a7433a31e0f33f936d15d6ad61437bc6"></a>文章


- 2020.03 [trustedsec] [Avoiding Get-InjectedThread for Internal Thread Creation](https://www.trustedsec.com/blog/avoiding-get-injectedthread-for-internal-thread-creation/)
- 2018.12 [pediy] [[原创]远程线程注入计算器](https://bbs.pediy.com/thread-248676.htm)
- 2018.04 [xpnsec] [PowerShell脚本Get-InjectedThread可枚举进程, 并判定进程是否被注入. 文章解释脚本监测原理, 以及绕过此种监测的方式](https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/)
- 2018.03 [pediy] [[原创]驱动注入用户线程之跨session通知csrss之真正解决](https://bbs.pediy.com/thread-225047.htm)
- 2017.10 [pediy] [[原创]ReflectiveLoader（远程线程的注入 PE的修正）](https://bbs.pediy.com/thread-222187.htm)
- 2017.05 [4hou] [免杀新姿势：利用线程将恶意代码注入到内存中](http://www.4hou.com/technology/4819.html)
- 2014.06 [dreamofareverseengineer] [Monitoring Thread Injection](http://dreamofareverseengineer.blogspot.com/2014/06/monitoring-thread-injection.html)
- 2009.10 [pediy] [[原创]老生常谈-远程线程注入](https://bbs.pediy.com/thread-98944.htm)
- 2006.02 [pediy] [[原创]ShellCode的另外一种玩法(远程线程注入ShellCode)](https://bbs.pediy.com/thread-21123.htm)


# <a id="02a1807b6a7131af27e3ed1002e7335a"></a>代码注入


***


## <a id="303ed79296c5af9c74cfd49dd31a399e"></a>工具


- [**6260**星][10d] [ObjC] [johnno1962/injectionforxcode](https://github.com/johnno1962/injectionforxcode) Runtime Code Injection for Objective-C & Swift
- [**2386**星][2y] [Py] [danmcinerney/lans.py](https://github.com/danmcinerney/lans.py) 注入代码并监视wifi用户
- [**1685**星][11d] [Py] [epinna/tplmap](https://github.com/epinna/tplmap) 代码注入和服务器端模板注入（Server-Side Template Injection）漏洞利用，若干沙箱逃逸技巧。
- [**1470**星][4m] [Swift] [johnno1962/injectioniii](https://github.com/johnno1962/injectioniii) 在(大部分)Swift4中重写Xcode的注入
- [**1112**星][14d] [ObjC] [dyci/dyci-main](https://github.com/dyci/dyci-main) Dynamic Code Injection Tool for Objective-C
- [**983**星][3y] [C] [cybellum/doubleagent](https://github.com/cybellum/doubleagent) Zero-Day Code Injection and Persistence Technique
- [**614**星][16d] [C++] [breakingmalwareresearch/atom-bombing](https://github.com/breakingmalwareresearch/atom-bombing) Brand New Code Injection for Windows
- [**265**星][5y] [C++] [breakingmalware/powerloaderex](https://github.com/breakingmalware/powerloaderex) Advanced Code Injection Technique for x32 / x64
- [**249**星][8y] [rentzsch/mach_star](https://github.com/rentzsch/mach_star) code injection and function overriding for Mac OS X
- [**228**星][12d] [C++] [marcosd4h/memhunter](https://github.com/marcosd4h/memhunter) Live hunting of code injection techniques
- [**214**星][17d] [C] [peperunas/injectopi](https://github.com/peperunas/injectopi) 一堆Windows 代码注入教程
- [**186**星][7m] [ObjC] [nakiostudio/twitterx](https://github.com/nakiostudio/twitterx) Keeping Twitter for macOS alive with code injection
- [**170**星][2y] [Py] [undeadsec/debinject](https://github.com/undeadsec/debinject) Inject malicious code into *.debs
- [**116**星][22d] [C#] [p0cl4bs/hanzoinjection](https://github.com/p0cl4bs/hanzoinjection) injecting arbitrary codes in memory to bypass common antivirus solutions
- [**91**星][2m] [Py] [hackatnow/cromos](https://github.com/hackatnow/cromos) 一个工具，下载合法的扩展Chrome网络商店和注入代码的应用程序的背景
- [**90**星][4y] [Java] [zerothoughts/spring-jndi](https://github.com/zerothoughts/spring-jndi) Proof of concept exploit, showing how to do bytecode injection through untrusted deserialization with Spring Framework 4.2.4
- [**66**星][2y] [Java] [sola-da/synode](https://github.com/sola-da/synode) Automatically Preventing Code Injection Attacks on Node.js
- [**65**星][3y] [Py] [sethsec/pycodeinjection](https://github.com/sethsec/pycodeinjection) Automated Python Code Injection Tool
- [**65**星][3m] [Py] [tbarabosch/quincy](https://github.com/tbarabosch/quincy) 在内存转储中检测基于主机的代码注入攻击
- [**49**星][2m] [C#] [guibacellar/dnci](https://github.com/guibacellar/dnci) DNCI - Dot Net Code Injector
- [**48**星][3y] [C++] [tonyzesto/pubgprivxcode85](https://github.com/tonyzesto/pubgprivxcode85) 简单chams wallhack为玩家未知的战场使用D3D11DrawIndexed钩子功能列表
- [**47**星][1y] [C] [yifanlu/3ds_injector](https://github.com/yifanlu/3ds_injector) Open source implementation of loader module with code injection support
- [**46**星][7m] [C] [rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine) Yet another code injection library for OS X
- [**37**星][2m] [C] [sduverger/ld-shatner](https://github.com/sduverger/ld-shatner) ld-linux code injector
- [**34**星][2y] [C++] [ntraiseharderror/dreadnought](https://github.com/ntraiseharderror/dreadnought) PoC for detecting and dumping code injection (built and extended on UnRunPE)
- [**27**星][4y] [Java] [zerothoughts/jndipoc](https://github.com/zerothoughts/jndipoc) Proof of concept showing how java byte code can be injected through InitialContext.lookup() calls
- [**27**星][6m] [Java] [dinject/dinject](https://github.com/dinject/dinject) Dependency injection via APT (source code generation) ala "Server side Dagger DI"
- [**25**星][7m] [Py] [batteryshark/miasma](https://github.com/batteryshark/miasma) Cross-Platform Binary OTF Patcher, Code Injector, Hacking Utility
- [**25**星][3y] [C++] [hatriot/delayloadinject](https://github.com/hatriot/delayloadinject) Code injection via delay load libraries
- [**20**星][2y] [c] [odzhan/propagate](https://github.com/odzhan/propagate) PROPagate code injection technique example
- [**19**星][3y] [Swift] [depoon/injectiblelocationspoofing](https://github.com/depoon/injectiblelocationspoofing) Location Spoofing codes for iOS Apps via Code Injection
- [**18**星][6y] [ObjC] [mhenr18/injector](https://github.com/mhenr18/injector) Code injection + payload communications for OSX (incl. sandboxed apps)
- [**17**星][2m] [C++] [sunsided/native-dotnet-code-injection](https://github.com/sunsided/native-dotnet-code-injection) Injection of managed code into non-managed Windows applications
- [**14**星][2m] [C#] [gerich-home/lua-inject](https://github.com/gerich-home/lua-inject) Inject any C# code into programs with lua
- [**13**星][3y] [C] [tbarabosch/1001-injects](https://github.com/tbarabosch/1001-injects) Tiny research project to understand code injections on Linux based systems
- [**13**星][3m] [C++] [revsic/codeinjection](https://github.com/revsic/codeinjection) Code Injection technique written in cpp language
- [**11**星][2y] [C] [gdbinit/calcspace](https://github.com/gdbinit/calcspace) Small util to calculate available free space in mach-o binaries for code injection
- [**11**星][7y] [C#] [yifanlu/vitainjector](https://github.com/yifanlu/vitainjector) Inject userland ARM code through PSM
- [**9**星][19d] [Py] [bao7uo/waf-cookie-fetcher](https://github.com/bao7uo/waf-cookie-fetcher) 一个用Python编写的Burp套件扩展，它使用一个无头浏览器来获取注入晶圆的cookie的值，这些cookie是通过客户端JavaScript代码在浏览器中计算出来的，并将它们添加到Burp的cookie jar中
- [**9**星][6m] [Py] [mpgn/cve-2018-16341](https://github.com/mpgn/cve-2018-16341) CVE-2018-16341 - Nuxeo Remote Code Execution without authentication using Server Side Template Injection
- [**7**星][2y] [PHP] [jpapayan/aspis](https://github.com/jpapayan/aspis) A PHP code transformer to provide protection against injection attacks
- [**6**星][2y] [Py] [andreafortuna/pycodeinjector](https://github.com/andreafortuna/pycodeinjector) Python code injection library
- [**4**星][1y] [Java] [righettod/injection-cheat-sheets](https://github.com/righettod/injection-cheat-sheets) Provide some tips to handle Injection into application code (OWASP TOP 10 - A1).
- [**2**星][2y] [Standard ML] [11digits/php-clean-malware](https://github.com/11digits/php-clean-malware) Simple PHP code to assist in cleaning of injected malware PHP code
- [**2**星][9m] [C++] [thepwnrip/code-injection](https://github.com/thepwnrip/code-injection) A collection of methods of Code Injection on Windows
- [**1**星][1y] [C++] [smore007/remote-iat-hook](https://github.com/smore007/remote-iat-hook) Remote IAT hook example. Useful for code injection
- [**None**星][Py] [thelinuxchoice/eviloffice](https://github.com/thelinuxchoice/eviloffice) Inject Macro and DDE code into Excel and Word documents (reverse shell)


***


## <a id="5e603e03f62d50e6fa8310e15470f233"></a>文章


- 2020.05 [hexacorn] [New Code Injection/Execution – Marsh…mellow](http://www.hexacorn.com/blog/2020/05/14/new-code-injection-execution-marsh-mellow/)
- 2020.04 [hexacorn] [Code Injection everyone forgets about](http://www.hexacorn.com/blog/2020/04/09/code-injection-everyone-forgets-about/)
- 2020.03 [WHIDInjector] [Remotely Injecting Keystrokes through an Industrial Barcode](https://www.youtube.com/watch?v=wJ1PFpHxA9Y)
- 2020.01 [hakin9] [Memhunter - Live Hunting Of Code Injection Techniques](https://hakin9.org/memhunter-live-hunting-of-code-injection-techniques/)
- 2020.01 [WarrantyVoider] [RE with WV - Episode #7 Binary Editing and Code Injection](https://www.youtube.com/watch?v=sRACOY3eRsU)
- 2019.12 [HackersOnBoard] [DEF CON 27 - Alon Weinberg - Please Inject Me a x64 Code Injection](https://www.youtube.com/watch?v=CMq4NQ2snNs)
- 2019.12 [sevagas] [Code Injection - Exploit WNF callback](https://blog.sevagas.com/?Code-Injection-Exploit-WNF-callback)
- 2019.12 [sevagas] [Code Injection - Disable Dynamic Code Mitigation (ACG)](https://blog.sevagas.com/?Code-Injection-Disable-Dynamic-Code-Mitigation-ACG)
- 2019.11 [ojasookert] [Macy’s, Magecart, Black Friday, and JavaScript Code Injection](https://medium.com/p/3c54ac741b0f)
- 2019.10 [talosintelligence] [YouPHPTube Encoder base64Url multiple command injections](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0917)
- 2019.09 [netsparker] [What is Code Injection and How to Avoid It](https://www.netsparker.com/blog/web-security/code-injection/)
- 2019.09 [aliyun] [初探代码注入](https://xz.aliyun.com/t/6253)
- 2019.08 [bugbountywriteup] [When i found php code injection](https://medium.com/p/87e8e30afe59)
- 2019.07 [bromium] [Dridex’s Bag of Tricks: An Analysis of its Masquerading and Code Injection Techniques](https://www.bromium.com/dridex-threat-analysis-july-2019-variant/)
- 2019.07 [aliyun] [Discuz!ML V3.X 代码注入分析](https://xz.aliyun.com/t/5638)
- 2019.06 [pewpewthespells] [Blocking Code Injection on iOS and OS X](https://pewpewthespells.com/blog/blocking_code_injection_on_ios_and_os_x.pdf)
- 2019.05 [hexacorn] [‘Plata o plomo’ code injections/execution tricks](http://www.hexacorn.com/blog/2019/05/26/plata-o-plomo-code-injections-execution-tricks/)
- 2019.05 [HackerSploit] [Bug Bounty Hunting - PHP Code Injection](https://www.youtube.com/watch?v=GE2HyC7Gwrs)
- 2019.04 [hexacorn] [SHLoadInProc – The Non-Working Code Injection trick from the past](http://www.hexacorn.com/blog/2019/04/30/shloadinproc-the-non-working-code-injection-trick-from-the-past/)
- 2019.04 [hexacorn] [Listplanting – yet another code injection trick](http://www.hexacorn.com/blog/2019/04/25/listplanting-yet-another-code-injection-trick/)
- 2019.04 [hexacorn] [3 new code injection tricks](http://www.hexacorn.com/blog/2019/04/24/3-new-code-injection-tricks/)
- 2019.04 [hexacorn] [Treepoline – new code injection technique](http://www.hexacorn.com/blog/2019/04/24/treepoline-new-code-injection-technique/)
- 2019.04 [hexacorn] [WordWarper – new code injection trick](http://www.hexacorn.com/blog/2019/04/23/wordwarper-new-code-injection-trick/)
- 2019.04 [JosephDelgadillo] [Learn System Hacking E6: PHP Code Injection](https://www.youtube.com/watch?v=paVE2Rx8mZI)
- 2019.03 [freebuf] [Java代码审计之SpEL表达式注入](https://www.freebuf.com/vuls/197008.html)
- 2019.03 [aditya12anand] [How to write secure code against injection attacks?](https://medium.com/p/aad4fff058da)
- 2019.03 [andreafortuna] [A simple Windows code Injection example written in C#](https://www.andreafortuna.org/programming/a-simple-windows-code-injection-example-written-in-c/)
- 2018.12 [360] [Linux Userland内存代码注入实践](https://www.anquanke.com/post/id/168204/)
- 2018.12 [aliyun] [HubL中的EL注入导致远程代码执行](https://xz.aliyun.com/t/3605)
- 2018.11 [aliyun] [[红日安全]代码审计Day17 - Raw MD5 Hash引发的注入](https://xz.aliyun.com/t/3375)
- 2018.11 [freebuf] [clrinject：向CLR Runtimes和AppDomain中注入代码的工具](https://www.freebuf.com/sectool/187541.html)
- 2018.10 [MSbluehat] [BlueHat v18 || Memory resident implants - code injection is alive and well](https://www.slideshare.net/MSbluehat/bluehat-v18-memory-resident-implants-code-injection-is-alive-and-well)
- 2018.09 [ironcastle] [More Excel DDE Code Injection, (Fri, Sep 28th)](https://www.ironcastle.net/more-excel-dde-code-injection-fri-sep-28th/)
- 2018.09 [sans] [More Excel DDE Code Injection](https://isc.sans.edu/forums/diary/More+Excel+DDE+Code+Injection/24150/)
- 2018.09 [bugbountywriteup] [Injecting tourism website running codeigniter](https://medium.com/p/e3c5370236c2)
- 2018.08 [andreafortuna] [pycodeinjector: a simple python Code Injection library](https://www.andreafortuna.org/programming/pycodeinjector-a-simple-python-code-injection-library/)
- 2018.08 [trustedsec] [Breaking Down the PROPagate Code Injection Attack](https://www.trustedsec.com/2018/08/breaking-down-the-propagate-code-injection-attack/)
- 2018.08 [andreafortuna] [Code injection on Windows using Python: a simple example](https://www.andreafortuna.org/programming/code-injection-on-windows-using-python-a-simple-example/)
- 2018.07 [4hou] [Firefox里的未知扩展正在将不需要的代码注入用户访问过的网站](http://www.4hou.com/vulnerable/12803.html)
- 2018.07 [aliyun] [服务器端电子表格注入 - 从公式注入到远程代码执行](https://xz.aliyun.com/t/2476)
- 2018.06 [bishopfox] [服务器端Spreadsheet注入: 利用公式注入实现RCE](https://www.bishopfox.com/blog/2018/06/server-side-spreadsheet-injections/)
- 2018.05 [freebuf] [黑客公布Signal通讯软件中的代码注入攻击](http://www.freebuf.com/news/171824.html)
- 2018.04 [freebuf] [PentesterLab新手教程（一）：代码注入](http://www.freebuf.com/sectool/168653.html)
- 2018.04 [4hou] [Early Bird代码注入可绕过杀毒软件检测](http://www.4hou.com/technology/11109.html)
- 2018.04 [freebuf] [$_SERVER[SCRIPT_NAME]变量可值注入恶意代码](http://www.freebuf.com/articles/web/166263.html)
- 2018.02 [360] [从概念到实际应用：详细讲解用户级API监控和代码注入检测方法](https://www.anquanke.com/post/id/98770/)
- 2018.01 [aliyun] [某电商前台代码注入](https://xz.aliyun.com/t/1982)
- 2018.01 [doyler] [Nodejs Code Injection (EverSec CTF – BSides Raleigh 2017)](https://www.doyler.net/security-not-included/nodejs-code-injection)
- 2018.01 [4hou] [星巴克挖矿事件分析：黑客是如何黑掉WiFi并将挖矿代码注入到HTML页面的？](http://www.4hou.com/wireless/9773.html)
- 2018.01 [4hou] [PoS端恶意软件LockPoS携新型代码注入技术强势回归](http://www.4hou.com/info/news/9774.html)
- 2018.01 [oherrala] [Using static typing to protect against code injection attacks](https://medium.com/p/353002ca6f2b)
- 2017.12 [4hou] [代码注入技术Process Doppelgänging利用介绍](http://www.4hou.com/technology/9379.html)
- 2017.12 [4hou] [新型代码注入攻击（Process Doppelgänging）：可绕过大多数AV检测](http://www.4hou.com/system/9183.html)
- 2017.11 [4hou] [Wi-Fi网络中，翻转照片，注入恶意代码到客户端](http://www.4hou.com/wireless/8559.html)
- 2017.11 [freebuf] [PROPagate：一种新的代码注入技巧介绍](http://www.freebuf.com/news/153041.html)
- 2017.11 [l0wb1tUC] [COD WWII Code Injection Fail](https://www.youtube.com/watch?v=ngeCZu4g4vw)
- 2017.11 [hexacorn] [PROPagate – a new code injection trick – 64-bit and 32-bit](http://www.hexacorn.com/blog/2017/11/03/propagate-a-new-code-injection-trick-64-bit-and-32-bit/)
- 2017.10 [4hou] [PROPagate——一种新的代码注入技巧](http://www.4hou.com/binary/8222.html)
- 2017.10 [hexacorn] [新的代码注入技巧 PROPagate](http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/)
- 2017.09 [decktonic] [How one hacker stole thousands of dollars worth of cryptocurrency with a classic code injection…](https://medium.com/p/a3aba5d2bff0)
- 2017.09 [freebuf] [LANs.py：一款可以实现代码注入，无线渗透和WiFi用户监控的强大工具](http://www.freebuf.com/sectool/147605.html)
- 2017.09 [arxiv] [[1709.05690] BabelView: Evaluating the Impact of Code Injection Attacks in Mobile Webviews](https://arxiv.org/abs/1709.05690)
- 2017.08 [defencely] [Achieving Code Injection on Trendy – Sarahah.com](https://defencely.com/blog/achieving-code-injection-on-trendy-sarahah-com/)
- 2017.07 [bogner] [Code Injection in Slack’s Windows Desktop Client leads to Privilege Escalation](https://bogner.sh/2017/07/code-injection-in-slacks-windows-desktop-client-leads-to-privilege-escalation/)
- 2017.06 [trendmicro] [勒索软件 SOREBRECT 分析。采用了“无文件”、利用 PsExec 注入代码等技术](https://blog.trendmicro.com/trendlabs-security-intelligence/analyzing-fileless-code-injecting-sorebrect-ransomware/)
- 2017.04 [welivesecurity] [Fake Chrome extensions inject code into web pages](https://www.welivesecurity.com/2017/04/28/fake-chrome-extensions-inject-code-web-pages/)
- 2017.04 [n0where] [Inject Custom Code Into PE File: InfectPE](https://n0where.net/inject-custom-code-into-pe-file-infectpe)
- 2017.03 [mstajbakhsh] [Smali Code Injection: Playing with 2048!](https://mstajbakhsh.ir/smali-code-injection-playing-with-2048/)
- 2017.03 [HackingMonks] [Remote Code Injection on DVWA medium](https://www.youtube.com/watch?v=eoZC5vsnTtw)
- 2017.03 [360] [AtomBombing：Windows的全新代码注入技术](https://www.anquanke.com/post/id/85675/)
- 2017.02 [360] [如何在.ipa文件上进行iOS代码注入](https://www.anquanke.com/post/id/85553/)
- 2017.01 [securiteam] [SSD Advisory – Icewarp, AfterLogic and MailEnable Code Injection](https://blogs.securiteam.com/index.php/archives/2937)
- 2017.01 [sentinelone] [What Is Code Injection?](https://www.sentinelone.com/blog/atombombing-code-injection-threat-hype/)
- 2017.01 [csyssec] [二进制代码注入PIN](http://www.csyssec.org/20170104/pinintro/)
- 2016.12 [mstajbakhsh] [Smali Code Injection](https://mstajbakhsh.ir/smali-code-injection/)
- 2016.12 [tevora] [Gaining Code Execution with Injection on Java args](http://threat.tevora.com/quick-tip-gaining-code-execution-with-injection-on-java-args/)
- 2016.11 [doyler] [Exploiting Python Code Injection in Web Applications](https://www.doyler.net/security-not-included/exploiting-python-code-injection)
- 2016.11 [kennethpoon] [How to perform iOS Code Injection on .ipa files](https://medium.com/p/1ba91d9438db)
- 2016.11 [thembits] [Loffice gets a makeover - Gives an insight into antis and detect code injection](http://thembits.blogspot.com/2016/11/loffice-gets-makeover-gives-insight.html)
- 2016.11 [360] [利用Python代码实现Web应用的注入](https://www.anquanke.com/post/id/84891/)
- 2016.11 [sethsec] [Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
- 2016.10 [360] [AtomBombing：全新的Windows代码注入技术](https://www.anquanke.com/post/id/84818/)
- 2016.10 [ensilo] [AtomBombing: A Code Injection that Bypasses Current Security Solutions](https://blog.ensilo.com/atombombing-a-code-injection-that-bypasses-current-security-solutions)
- 2016.10 [venus] [代码审计就该这么来 - 2 Mlecms 注入](https://paper.seebug.org/78/)
- 2016.10 [insinuator] [Linq Injection – From Attacking Filters to Code Execution](https://insinuator.net/2016/10/linq-injection-from-attacking-filters-to-code-execution/)
- 2016.10 [polaris] [PHP Code Injection Analysis](http://polaris-lab.com/index.php/archives/254/)
- 2016.10 [JackkTutorials] [How to perform Remote Code Injection attacks *REUPLOADED*](https://www.youtube.com/watch?v=AuNwk--lfxU)
- 2016.09 [forcepoint] [Highly Evasive Code Injection Awaits User Interaction Before Delivering Malware](https://www.forcepoint.com/blog/security-labs/highly-evasive-code-injection-awaits-user-interaction-delivering-malware)
- 2016.08 [artsploit] [[demo.paypal.com] Node.js code injection (RCE)](http://artsploit.blogspot.com/2016/08/pprce2.html)
- 2016.07 [suchakra] [Unravelling Code Injection in Binaries](https://suchakra.wordpress.com/2016/07/03/unravelling-code-injection-in-binaries/)
- 2016.03 [yifan] [3DS Code Injection through "Loader"](http://yifan.lu/2016/03/28/3ds-code-injection-through-loader/)
- 2015.12 [hexacorn] [IME code injection (old)](http://www.hexacorn.com/blog/2015/12/17/ime-code-injection-old/)
- 2015.08 [securiteam] [SSD Advisory – Symantec NetBackup OpsCenter Server Java Code Injection RCE](https://blogs.securiteam.com/index.php/archives/2557)
- 2015.04 [sensecy] [MitM Attacks Pick Up Speed – A Russian Coder Launches a New Web Injection Coding Service](https://blog.sensecy.com/2015/04/21/mitm-attacks-pick-up-speed-a-russian-coder-launches-a-new-web-injection-coding-service/)
- 2015.03 [pediy] [[原创]代码注入器源码献上](https://bbs.pediy.com/thread-198771.htm)
- 2014.12 [] [逐浪CMS2个文件两个注入5处问题代码 另附其他注入绕过方式](http://0day5.com/archives/2627/)
- 2014.11 [] [代码审计：大米CMS注入](http://www.91ri.org/11542.html)
- 2014.10 [arxiv] [[1410.7756] Code Injection Attacks on HTML5-based Mobile Apps](https://arxiv.org/abs/1410.7756)
- 2014.09 [tribalchicken] [Bash bug allows code injection attack](https://tribalchicken.io/bash-bug-allows-code-injection-attack/)
- 2014.09 [digitaloperatives] [OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection: Local Use](https://www.digitaloperatives.com/2014/09/25/os-x-vmware-fusion-privilege-escalation-via-bash-environment-code-injection/)
- 2014.09 [tribalchicken] [Bash bug allows code injection attack](https://tribalchicken.net/bash-bug-allows-code-injection-attack/)
- 2014.08 [] [HTML5 App的代码注入攻击](http://www.91ri.org/10496.html)
- 2014.03 [pediy] [[原创]对笔记本 Inject code 实验](https://bbs.pediy.com/thread-185635.htm)
- 2014.01 [] [U-Mail注入之任意代码写入exp](http://0day5.com/archives/1210/)
- 2013.12 [lowleveldesign] [Injecting code into .NET applications](https://lowleveldesign.org/2013/12/28/injecting-code-into-net-applications/)
- 2013.11 [imperva] [Threat Advisory: A JBoss AS Exploit, Web Shell code Injection.](https://www.imperva.com/blog/2013/11/threat-advisory-a-jboss-as-exploit-web-shell-code-injection/)
- 2013.08 [scotthelme] [Code Injection - TLS (SSL) is not all about privacy, it's about integrity too](https://scotthelme.co.uk/ssl-about-integrity-too/)
- 2013.08 [sans] [BBCode tag "[php]" used to inject php code](https://isc.sans.edu/forums/diary/BBCode+tag+php+used+to+inject+php+code/16291/)
- 2013.05 [hackingarticles] [Exploit Remote PC using Firefox 17.0.1 + Flash Privileged Code Injection](http://www.hackingarticles.in/exploit-remote-pc-using-firefox-17-0-1-flash-privileged-code-injection/)
- 2013.04 [freebuf] [[php 代码审计]Espcms 暴力注入](http://www.freebuf.com/vuls/8185.html)
- 2013.03 [pediy] [[原创]手机毒霸去广告功能分析三：java代码（dex）注入](https://bbs.pediy.com/thread-166480.htm)
- 2012.12 [hackingarticles] [Bypassing Antivirus using Multi Pyinjector Shell Code Injection in SET Toolkit](http://www.hackingarticles.in/bypassing-antivirus-using-multi-pyinjector-shellcode-injection-in-set-toolkit/)
- 2012.12 [freebuf] [向正在运行的Linux应用程序注入代码](http://www.freebuf.com/articles/system/6388.html)
- 2012.11 [debasish] [Suicide via Remote Code Injection](http://www.debasish.in/2012/11/suicide-via-remote-code-injection.html)
- 2012.10 [volatility] [Reverse Engineering Poison Ivy's Injected Code Fragments](https://volatility-labs.blogspot.com/2012/10/reverse-engineering-poison-ivys.html)
- 2012.08 [cert] [More human than human – Flame’s code injection techniques](https://www.cert.pl/en/news/single/more-human-than-human-flames-code-injection-techniques/)
- 2012.07 [welivesecurity] [Rovnix.D: the code injection story](https://www.welivesecurity.com/2012/07/27/rovnix-d-the-code-injection-story/)
- 2012.06 [welivesecurity] [ZeroAccess: code injection chronicles](https://www.welivesecurity.com/2012/06/25/zeroaccess-code-injection-chronicles/)
- 2012.06 [freebuf] [[方法分享]利用输入框进行恶意代码注入](http://www.freebuf.com/articles/4316.html)
- 2012.06 [hackingarticles] [How to Attack on Remote PC using HTTP Code Injection Technique](http://www.hackingarticles.in/how-to-attack-on-remote-pc-using-http-code-injection-technique/)
- 2012.04 [pediy] [[原创]今天突然想注入，写了点代码](https://bbs.pediy.com/thread-148886.htm)
- 2012.02 [trustwave] [[Honeypot Alert] phpMyAdmin Code Injection Attacks for Botnet Recruitment](https://www.trustwave.com/Resources/SpiderLabs-Blog/-Honeypot-Alert--phpMyAdmin-Code-Injection-Attacks-for-Botnet-Recruitment/)
- 2011.12 [pediy] [[原创]自己写的一个为可执行文件注入代码的API，使用超级方便](https://bbs.pediy.com/thread-143691.htm)
- 2011.07 [pediy] [[原创]借腹怀胎的注入代码个人理解](https://bbs.pediy.com/thread-137090.htm)
- 2011.06 [forcepoint] [Malware campaign uses direct injection of Java exploit code](https://www.forcepoint.com/blog/security-labs/malware-campaign-uses-direct-injection-java-exploit-code)
- 2010.05 [pediy] [[翻译]注入你的代码到可执行文件](https://bbs.pediy.com/thread-113871.htm)
- 2009.03 [pediy] [[原创]如何向WM程序注入代码[1]总纲](https://bbs.pediy.com/thread-84327.htm)
- 2009.01 [arxiv] [[0901.3482] Code injection attacks on harvard-architecture devices](https://arxiv.org/abs/0901.3482)
- 2008.11 [travisgoodspeed] [MicaZ Code Injection](http://travisgoodspeed.blogspot.com/2008/11/micaz-code-injection.html)
- 2008.09 [secshoggoth] [SEO Code Injection](http://secshoggoth.blogspot.com/2008/09/seo-code-injection.html)
- 2008.07 [reverse] [Mac OS X Code injection](https://reverse.put.as/2008/07/03/mac-os-x-code-injection/)
- 2007.09 [travisgoodspeed] [Memory-Constrained Code Injection](http://travisgoodspeed.blogspot.com/2007/09/memory-constrained-code-injection.html)
- 2007.02 [sans] [more code injection sites 8.js](https://isc.sans.edu/forums/diary/more+code+injection+sites+8js/2178/)
- 2006.12 [pediy] [[翻译]注入 动态生成及混淆的恶意代码的检测](https://bbs.pediy.com/thread-35766.htm)
- 2006.08 [pediy] [[翻译]向导入表中注入代码](https://bbs.pediy.com/thread-30166.htm)
- 2006.04 [pediy] [翻译：向PE中注入代码（4.17修改）](https://bbs.pediy.com/thread-24183.htm)
- 2005.07 [pediy] [Code Injection破解Armadillo V4.20单进程加壳程序――FTPRush Unicode V1.0.RC6.build.568](https://bbs.pediy.com/thread-15403.htm)
- 2005.06 [pediy] [Hying's Armor v0.7x Code Injection](https://bbs.pediy.com/thread-14294.htm)
- 2005.05 [pediy] [EnCryptPE v2 Code injection](https://bbs.pediy.com/thread-13896.htm)
- 2005.05 [pediy] [ARM3.7x-4.1CopyMEMII Code injection](https://bbs.pediy.com/thread-13656.htm)
- 2005.04 [pediy] [OBSIDIUM 1.25 Code Injection](https://bbs.pediy.com/thread-13283.htm)
- 2005.04 [pediy] [Armadillo 3.7X-4.X Code Injection](https://bbs.pediy.com/thread-13280.htm)
- 2004.09 [pediy] [[翻译]利用代码注入脱壳](https://bbs.pediy.com/thread-4541.htm)


# <a id="a5458e6ee001b754816237b9a2108569"></a>Shellcode注入


***


## <a id="28e1b534eae8d37d8fc1d212f0db0263"></a>工具


- [**2209**星][4m] [Py] [trustedsec/unicorn](https://github.com/trustedsec/unicorn) 通过PowerShell降级攻击, 直接将Shellcode注入到内存
- [**476**星][21d] [Py] [trustedsec/meterssh](https://github.com/trustedsec/meterssh) 将Shellcode注入内存，然后通过SSH隧道传输（端口任选，并伪装成普通SSH连接）
- [**225**星][4m] [PS] [outflanknl/excel4-dcom](https://github.com/outflanknl/excel4-dcom) PowerShell和Cobalt Strike脚本，通过DCOM执行Excel4.0/XLM宏实现横向渗透（直接向Excel.exe注入Shellcode）
- [**112**星][2m] [C++] [josh0xa/threadboat](https://github.com/josh0xA/ThreadBoat) 使用线程执行劫持将本机shellcode注入到标准的Win32应用程序中
- [**77**星][4m] [C] [dimopouloselias/simpleshellcodeinjector](https://github.com/dimopouloselias/simpleshellcodeinjector) 接收十六进制的shellcode作为参数并执行它
- [**66**星][2m] [Py] [sensepost/anapickle](https://github.com/sensepost/anapickle) 用Python的Pickle语言编写shellcode和操作Pickle注入shellcode的工具集。
- [**43**星][1m] [Py] [borjamerino/tlsinjector](https://github.com/borjamerino/tlsinjector) Python script to inject and run shellcodes through TLS callbacks
- [**27**星][2y] [Py] [taroballzchen/shecodject](https://github.com/TaroballzChen/shecodject) shecodject is a autoscript for shellcode injection by Python3 programing
- [**19**星][5y] [C] [jorik041/cymothoa](https://github.com/jorik041/cymothoa) Cymothoa is a backdooring tool, that inject backdoor's shellcode directly into running applications. Stealth and lightweight...
- [**16**星][9m] [PLpgSQL] [michaelburge/redshift-shellcode](https://github.com/michaelburge/redshift-shellcode) Example of injecting x64 shellcode into Amazon Redshift
- [**10**星][1y] [C++] [egebalci/injector](https://github.com/egebalci/injector) Simple shellcode injector.
- [**4**星][3y] [Shell] [thepisode/linux-shellcode-generator](https://github.com/thepisode/linux-shellcode-generator) Experiments on Linux Assembly shellcodes injection
- [**None**星][Go] [pioneerhfy/goback](https://github.com/pioneerhfy/goback) GOback is a backdoor written in GO that use shellcode injection technique for achiving its task.


***


## <a id="c6942bb5275f5b62a41238c6042b2b81"></a>文章


- 2020.03 [hakin9] [Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory.](https://hakin9.org/unicorn-is-a-simple-tool-for-using-a-powershell-downgrade-attack-and-inject-shellcode-straight-into-memory/)
- 2019.12 [aliyun] [手工shellcode注入PE文件](https://xz.aliyun.com/t/6939)
- 2019.11 [4hou] [代码注入技术之Shellcode注入](https://www.4hou.com/web/21784.html)
- 2019.11 [ColinHardy] [Excel 4.0 Macros Analysis - Cobalt Strike Shellcode Injection](https://www.youtube.com/watch?v=XnN_UWfHlNM)
- 2019.06 [360] [Arm平台Ptrace注入shellcode技术](https://www.anquanke.com/post/id/179985/)
- 2018.09 [pediy] [[分享]绝对牛逼哄哄的shellcode内存注入,支持64,32,远程内存注入,支持VMP壳最大强度保护](https://bbs.pediy.com/thread-246934.htm)
- 2018.05 [cobaltstrike] [PowerShell Shellcode Injection on Win 10 (v1803)](https://blog.cobaltstrike.com/2018/05/24/powershell-shellcode-injection-on-win-10-v1803/)
- 2017.12 [pentesttoolz] [Shecodject – Autoscript for Shellcode Injection](https://pentesttoolz.com/2017/12/30/shecodject-autoscript-for-shellcode-injection/)
- 2017.12 [MalwareAnalysisForHedgehogs] [Malware Analysis - ROKRAT Unpacking from Injected Shellcode](https://www.youtube.com/watch?v=uoBQE5s2ba4)
- 2017.11 [freebuf] [Metasploit自动化Bypass Av脚本：Shecodject X Shellcode Injection](http://www.freebuf.com/sectool/154356.html)
- 2017.01 [christophertruncer] [Shellcode Generation, Manipulation, and Injection in Python 3](https://www.christophertruncer.com/shellcode-manipulation-and-injection-in-python-3/)
- 2015.12 [dhavalkapil] [Shellcode Injection](https://dhavalkapil.com/blogs/Shellcode-Injection/)
- 2015.12 [n0where] [Dynamic Shellcode Injection: Shellter](https://n0where.net/dynamic-shellcode-injection-shellter)
- 2015.10 [freebuf] [Kali Shellter 5.1：动态ShellCode注入工具 绕过安全软件](http://www.freebuf.com/sectool/81955.html)
- 2015.07 [BsidesLisbon] [BSidesLisbon2015 - Shellter - A dynamic shellcode injector - Kyriakos Economou](https://www.youtube.com/watch?v=TunWNHYrWp8)
- 2015.06 [freebuf] [动态Shellcode注入工具 – Shellter](http://www.freebuf.com/sectool/71230.html)
- 2015.06 [shelliscoming] [TLS Injector: running shellcodes through TLS callbacks](http://www.shelliscoming.com/2015/06/tls-injector-running-shellcodes-through.html)
- 2014.08 [toolswatch] [Shellter v1.7 A Dynamic ShellCode Injector – Released](http://www.toolswatch.org/2014/08/shellter-v1-7-a-dynamic-shellcode-injector-released/)
- 2014.06 [toolswatch] [[New Tool] Shellter v1.0 A Dynamic ShellCode Injector – Released](http://www.toolswatch.org/2014/06/new-tool-shellter-v1-0-a-dynamic-shellcode-injector-released/)
- 2013.06 [debasish] [Injecting Shellcode into a Portable Executable(PE) using Python](http://www.debasish.in/2013/06/injecting-shellcode-into-portable.html)
- 2013.05 [trustedsec] [Native PowerShell x86 Shellcode Injection on 64-bit Platforms](https://www.trustedsec.com/2013/05/native-powershell-x86-shellcode-injection-on-64-bit-platforms/)
- 2013.05 [pediy] [[原创]内核ShellCode注入的一种方法](https://bbs.pediy.com/thread-170959.htm)
- 2012.10 [hackingarticles] [Cymothoa – Runtime shellcode injection Backdoors](http://www.hackingarticles.in/cymothoa-runtime-shellcode-injection-for-stealthy-backdoors/)
- 2012.09 [hackingarticles] [PyInjector Shellcode Injection attack on Remote PC using Social Engineering Toolkit](http://www.hackingarticles.in/pyinjector-shellcode-injection-attack-on-remote-windows-pc-using-social-engineering-toolkit/)
- 2012.08 [trustedsec] [New tool PyInjector Released – Python Shellcode Injection](https://www.trustedsec.com/2012/08/new-tool-pyinjector-released-python-shellcode-injection/)
- 2007.01 [pediy] [《The Shellcoder's handbook》第十四章_故障注入](https://bbs.pediy.com/thread-38713.htm)


# <a id="3584002eaa30b92479c1e1c2fc6ce4ef"></a>ELF注入


***


## <a id="b423b830472372349203f88cf64c6814"></a>工具


- [**269**星][10d] [Shell] [cytopia/pwncat](https://github.com/cytopia/pwncat) pwncat - netcat on steroids with Firewall, IDS/IPS evasion, bind and reverse shell, self-injecting shell and port forwarding magic - and its fully scriptable with Python (PSE)
- [**106**星][14d] [C] [comsecuris/luaqemu](https://github.com/comsecuris/luaqemu) QEMU-based framework exposing several of QEMU-internal APIs to a LuaJIT core injected into QEMU itself. Among other things, this allows fast prototyping of target systems without any native code and minimal effort in Lua.
- [**73**星][10d] [C] [zznop/drow](https://github.com/zznop/drow) Injects code into ELF executables post-build
- [**45**星][1m] [C] [jmpews/evilelf](https://github.com/jmpews/evilelf) Malicious use of ELF such as .so inject, func hook and so on.
- [**26**星][4m] [C++] [shaxzy/nixware-csgo](https://github.com/shaxzy/nixware-csgo) Source code of Nixware. Cheat doesn't inject for some reason, fix it uself or just paste from it
- [**9**星][3m] [C] [mfaerevaag/elfinjector](https://github.com/mfaerevaag/elfinjector) Code injector for ELF binaries (incl. PIE)
- [**1**星][2y] [JS] [mshoop/web-xss-attack](https://github.com/mshoop/web-xss-attack) Exploring website security through cross-site scripting attacks, maliciously injected JavaScript and self-propagating worms


***


## <a id="0a853f9e3f9ccb0663007d3a508ce02b"></a>文章


- 2020.02 [advancedpersistentjest] [Fault Injection on Linux: Practical KERNELFAULT-Style Attacks](https://advancedpersistentjest.com/2020/02/15/fault-injection-on-linux-practical-kernelfault-style-attacks/)
- 2018.08 [0x00sec] [Issues with elf file injection tutorial by pico](https://0x00sec.org/t/issues-with-elf-file-injection-tutorial-by-pico/8029/)
- 2017.12 [MSbluehat] [BlueHat v17 || KERNELFAULT: R00ting the Unexploitable using Hardware Fault Injection](https://www.slideshare.net/MSbluehat/kernelfault-r00ting-the-unexploitable-using-hardware-fault-injection)
- 2016.05 [0x00sec] [ELFun File Injector](https://0x00sec.org/t/elfun-file-injector/410/)
- 2016.04 [backtrace] [ELF shared library injection forensics](https://backtrace.io/blog/backtrace/elf-shared-library-injection-forensics/)
- 2014.02 [malwarebytes] [How to Unpack a Self-Injecting Citadel Trojan](https://blog.malwarebytes.com/threat-analysis/2014/02/how-to-unpack-a-self-injecting-citadel-trojan/)
- 2014.02 [evilsocket] [Termination and Injection Self Defense on Windows >= Vista SP1](https://www.evilsocket.net/2014/02/05/termination-and-injection-self-defense-on-windows/)
- 2010.03 [publicintelligence] [ELF/VLF Wave-injection and Magnetospheric Probing with HAARP](https://publicintelligence.net/elfvlf-wave-injection-and-magnetospheric-probing-with-haarp/)


# <a id="108c798de24e7ce6fde0cafe99eec5b3"></a>Dylib注入


***


## <a id="12df48702564d73c275c72133546d73e"></a>工具


- [**2032**星][3y] [Swift] [urinx/iosapphook](https://github.com/urinx/iosapphook) 专注于非越狱环境下iOS应用逆向研究，从dylib注入，应用重签名到App Hook
- [**752**星][5y] [ObjC] [kjcracks/yololib](https://github.com/kjcracks/yololib) dylib injector for mach-o binaries
- [**506**星][13d] [Objective-C++] [bishopfox/bfinject](https://github.com/bishopfox/bfinject) Dylib injection for iOS 11.0 - 11.1.2 with LiberiOS and Electra jailbreaks
- [**191**星][3m] [Swift] [codesourse/iinjection](https://github.com/codesourse/iinjection)  an app for OS X that can inject dylib and (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.
- [**173**星][16d] [C] [scen/osxinj](https://github.com/scen/osxinj) osx dylib injection


***


## <a id="0af1332c6476d1a8f98046542e925282"></a>文章


- 2014.05 [pediy] [[原创]iOS下远程进程注入dylib源码](https://bbs.pediy.com/thread-187833.htm)


# <a id="06fc9c584b797f97731e3c49886dcc08"></a>Android


***


## <a id="4c02a0ba65fa4f582ec590ce1e070822"></a>工具


- [**1300**星][4m] [JS] [megatronking/httpcanary](https://github.com/megatronking/httpcanary) 一个强大的捕获和注入工具的Android平台
- [**475**星][3y] [Smali] [sensepost/kwetza](https://github.com/sensepost/kwetza) Python 脚本，将 Meterpreter payload 注入 Andorid App
- [**447**星][9m] [Java] [megatronking/netbare](https://github.com/megatronking/netbare) Net packets capture & injection library designed for Android
- [**252**星][16d] [Py] [feicong/jni_helper](https://github.com/feicong/jni_helper) AndroidSO自动化分析工具（非虫）
- [**148**星][4m] [Java] [zhouat/inject-hook](https://github.com/zhouat/inject-hook) for android
- [**144**星][3y] [C] [xmikos/setools-android](https://github.com/xmikos/setools-android) Unofficial port of setools to Android with additional sepolicy-inject utility included
- [**136**星][11d] [Lua] [lanoox/luject](https://github.com/lanoox/luject) A static injector of dynamic library for application (android, iphoneos, macOS, windows, linux)
- [**122**星][5y] [irsl/adb-backup-apk-injection](https://github.com/irsl/adb-backup-apk-injection) Android ADB backup APK Injection POC
- [**97**星][4y] [Shell] [jlrodriguezf/whatspwn](https://github.com/jlrodriguezf/whatspwn) Linux tool used to extract sensitive data, inject backdoor or drop remote shells on android devices.
- [**76**星][4y] [Py] [moosd/needle](https://github.com/moosd/needle) Android framework injection made easy
- [**56**星][4m] [C] [shunix/tinyinjector](https://github.com/shunix/tinyinjector) Shared Library Injector on Android
- [**55**星][4m] [Java] [igio90/fridaandroidinjector](https://github.com/igio90/fridaandroidinjector) Inject frida agents on local processes through an Android app
- [**52**星][2m] [Py] [alessandroz/pupy](https://github.com/alessandroz/pupy) Python编写的远控、后渗透工具，跨平台（Windows, Linux, OSX, Android）
- [**52**星][14d] [TS] [whid-injector/whid-mobile-connector](https://github.com/whid-injector/whid-mobile-connector) Android Mobile App for Controlling WHID Injector remotely.
- [**48**星][16d] [Py] [ikoz/jdwp-lib-injector](https://github.com/ikoz/jdwp-lib-injector) inject native shared libraries into debuggable Android applications
- [**46**星][30d] [Shell] [jbreed/apkinjector](https://github.com/jbreed/apkinjector) Android APK Antivirus evasion for msfvenom generated payloads to inject into another APK file for phishing attacks.
- [**40**星][8m] [Java] [ivianuu/contributer](https://github.com/ivianuu/contributer) Inject all types like views or a conductor controllers with @ContributesAndroidInjector
- [**33**星][1y] [Groovy] [eastwoodyang/autoinject](https://github.com/eastwoodyang/autoinject) Android 通用的组件自动注册、自动初始化解决方案
- [**30**星][6m] [Java] [cristianturetta/mad-spy](https://github.com/cristianturetta/mad-spy) 一个用于教育目的的恶意软件
- [**24**星][5m] [Smali] [aress31/sci](https://github.com/aress31/sci) 用于在Android应用程序中自动化汇编代码注入(trojanting)过程的框架
- [**13**星][11m] [JS] [cheverebe/android-malware](https://github.com/cheverebe/android-malware) Injected malicious code into legitimate andoid applications. Converted a keyboard app into a keylogger and an MP3 downloader into an image thief.


***


## <a id="9ff27f3143a5c619b554185069ecffb0"></a>文章


- 2018.01 [pediy] [[分享][原创]修改android app_process elf (实现rrrfff大神 <android全局注入>第一步)](https://bbs.pediy.com/thread-224297.htm)
- 2017.08 [360] [Dvmap：第一款使用代码注入的Android恶意软件](https://www.anquanke.com/post/id/86648/)
- 2017.06 [4hou] [小心！Google Play 中出现首个使用代码注入Android恶意软件——Dvmap](http://www.4hou.com/vulnerable/5364.html)
- 2017.06 [securelist] [卡巴斯基首次发现代码注入的 Android 恶意 App：运行时将恶意代码注入系统库 libdmv.so 或者 libandroid_runtime.so。此恶意 App 甚至支持64位 Android 系统](https://securelist.com/dvmap-the-first-android-malware-with-code-injection/78648/)
- 2015.05 [evilsocket] [Android Native API Hooking With Library Injection and ELF Introspection.](https://www.evilsocket.net/2015/05/04/android-native-api-hooking-with-library-injecto/)
- 2015.05 [evilsocket] [Dynamically Inject a Shared Library Into a Running Process on Android/ARM](https://www.evilsocket.net/2015/05/01/dynamically-inject-a-shared-library-into-a-running-process-on-androidarm/)
- 2011.10 [pediy] [[原创]发个Android平台上的注入代码](https://bbs.pediy.com/thread-141355.htm)
- 2011.09 [winsunxu] [android注入代码之注入类方法](https://blog.csdn.net/winsunxu/article/details/6771905)
- 2011.09 [winsunxu] [android注入代码，再议寄存器平衡](https://blog.csdn.net/winsunxu/article/details/6756857)
- 2011.09 [winsunxu] [android 代码注入 崩溃 解决方法](https://blog.csdn.net/winsunxu/article/details/6742838)


# <a id="4ffa5c3eb1f3b85e4c38f6863f5b76b2"></a>其他


***


## <a id="fd5f8ada2d4f47c63c3635427873c79c"></a>工具


- [**1044**星][11d] [Go] [banzaicloud/bank-vaults](https://github.com/banzaicloud/bank-vaults) A Vault swiss-army knife: a K8s operator, Go client with automatic token renewal, automatic configuration, multiple unseal options and more. A CLI tool to init, unseal and configure Vault (auth methods, secret engines). Direct secret injection into Pods.
- [**980**星][12d] [Perl] [infobyte/evilgrade](https://github.com/infobyte/evilgrade) 供应链攻击: 注入虚假的update
- [**920**星][4m] [C++] [whid-injector/whid](https://github.com/whid-injector/whid) WiFi HID Injector - An USB Rubberducky / BadUSB On Steroids.
- [**877**星][7m] [C] [spacehuhn/wifi_ducky](https://github.com/spacehuhn/wifi_ducky) 使用ESP8266 + ATMEGA32U4，远程上传、保存和运行按键注入Payload
- [**577**星][19d] [TS] [samdenty/injectify](https://github.com/samdenty/injectify) 对网站实行中间人攻击的框架
- [**559**星][28d] [Py] [shellphish/fuzzer](https://github.com/shellphish/fuzzer) Americanfuzzy lop 的 Python 版本接口
- [**555**星][11d] [C] [libnet/libnet](https://github.com/libnet/libnet) 创建和注入网络数据包
- [**509**星][10d] [C] [nongiach/sudo_inject](https://github.com/nongiach/sudo_inject) [Linux] Two Privilege Escalation techniques abusing sudo token
- [**501**星][7m] [C] [hasherezade/demos](https://github.com/hasherezade/demos) Demos of various injection techniques found in malware
- [**463**星][12d] [Perl] [chinarulezzz/pixload](https://github.com/chinarulezzz/pixload) Image Payload Creating/Injecting tools
- [**427**星][11d] [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list) 一种攻击，其目标是通过易受攻击的应用程序在主机操作系统上执行任意命令
- [**420**星][2y] [C++] [rootm0s/injectors](https://github.com/rootm0s/injectors) DLL/Shellcode injection techniques
- [**380**星][15d] [veracode-research/solr-injection](https://github.com/veracode-research/solr-injection) Apache Solr注入研究
- [**380**星][15d] [veracode-research/solr-injection](https://github.com/veracode-research/solr-injection) Apache Solr Injection Research
- [**356**星][8d] [C++] [spacehuhntech/wifiduck](https://github.com/SpacehuhnTech/WiFiDuck) Wireless keystroke injection attack platform
- [**320**星][2y] [C++] [exploitagency/esploitv2](https://github.com/exploitagency/esploitv2) 为Atmega 32u4/ESP8266通过串口配对设计的WiFi按键注射工具(Cactus WHID固件)。还提供了串行、HTTP和PASV FTP过滤方法，以及名为ESPortal的集成凭据收割机钓鱼工具。
- [**317**星][10d] [Py] [pmsosa/duckhunt](https://github.com/pmsosa/duckhunt) Prevent RubberDucky (or other keystroke injection) attacks
- [**308**星][12d] [C] [pulkin/esp8266-injection-example](https://github.com/pulkin/esp8266-injection-example) Example project to demonstrate packet injection / sniffer capabilities of ESP8266 IC.
- [**299**星][18d] [HTML] [dxa4481/cssinjection](https://github.com/dxa4481/cssinjection) Stealing CSRF tokens with CSS injection (without iFrames)
- [**297**星][2y] [C] [can1357/theperfectinjector](https://github.com/can1357/theperfectinjector) Literally, the perfect injector.
- [**284**星][4m] [C++] [fransbouma/injectablegenericcamerasystem](https://github.com/fransbouma/injectablegenericcamerasystem) This is a generic camera system to be used as the base for cameras for taking screenshots within games. The main purpose of the system is to hijack the in-game 3D camera by overwriting values in its camera structure with our own values so we can control where the camera is located, it's pitch/yaw/roll values, its FoV and the camera's look vector.
- [**265**星][19d] [C] [astsam/rtl8812au](https://github.com/astsam/rtl8812au) RTL8812AU/21AU and RTL8814AU driver with monitor mode and frame injection
- [**265**星][17d] [Java] [portswigger/collaborator-everywhere](https://github.com/portswigger/collaborator-everywhere) Burp Suite 扩展，通过注入非侵入性 headers 来增强代理流量，通过引起 Pingback 到 Burp Collaborator 来揭露后端系统
- [**264**星][2y] [Py] [thetwitchy/xxer](https://github.com/thetwitchy/xxer) A blind XXE injection callback handler. Uses HTTP and FTP to extract information. Originally written in Ruby by ONsec-Lab.
- [**255**星][14d] [Py] [nteseyes/pylane](https://github.com/nteseyes/pylane) An python vm injector with debug tools, based on gdb.
- [**254**星][16d] [C] [klsecservices/invoke-vnc](https://github.com/klsecservices/Invoke-Vnc)  executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. 
- [**242**星][11d] [JS] [sjitech/proxy-login-automator](https://github.com/sjitech/proxy-login-automator) A single node.js script to automatically inject user/password to http proxy server via a local forwarder
- [**215**星][12d] [Py] [google/ukip](https://github.com/google/ukip) USB Keystroke Injection Protection
- [**212**星][2y] [HTML] [xsscx/commodity-injection-signatures](https://github.com/xsscx/commodity-injection-signatures) Commodity Injection Signatures, Malicious Inputs, XSS, HTTP Header Injection, XXE, RCE, Javascript, XSLT
- [**211**星][12d] [C++] [hiitiger/gelectron](https://github.com/hiitiger/gelectron) gameoverlay solution for Electron, Qt and CEF, just like discord game overlay and steam game overlay, inject any app to overlay in your game
- [**197**星][5y] [Py] [offensivepython/pinject](https://github.com/OffensivePython/Pinject) Raw Packet Injection tool
- [**170**星][3y] [HTML] [threatexpress/metatwin](https://github.com/threatexpress/metatwin) The project is designed as a file resource cloner. Metadata, including digital signature, is extracted from one file and injected into another.
- [**158**星][11d] [C] [aircrack-ng/rtl8188eus](https://github.com/aircrack-ng/rtl8188eus) RealTek RTL8188eus WiFi driver with monitor mode & frame injection support
- [**157**星][7d] [icehacks/survivcheatinjector](https://github.com/icehacks/survivcheatinjector) An actual, updated, surviv.io cheat. Works great and we reply fast.
- [**149**星][25d] [Shell] [depoon/iosdylibinjectiondemo](https://github.com/depoon/iosdylibinjectiondemo) Using this Repository to demo how to inject dynamic libraries into cracked ipa files for jailed iOS devices
- [**144**星][2m] [Py] [shengqi158/pyvulhunter](https://github.com/shengqi158/pyvulhunter) python audit tool 审计 注入 inject
- [**141**星][18d] [Ruby] [dry-rb/dry-auto_inject](https://github.com/dry-rb/dry-auto_inject) Container-agnostic constructor injection mixin
- [**140**星][12d] [Go] [malfunkt/arpfox](https://github.com/malfunkt/arpfox) An arpspoof alternative (written in Go) that injects spoofed ARP packets into a LAN.
- [**135**星][16d] [Py] [cr0hn/enteletaor](https://github.com/cr0hn/enteletaor) Message Queue & Broker Injection tool
- [**134**星][3m] [C++] [michalmonday/supremeduck](https://github.com/michalmonday/supremeduck) USB keystroke injector controlled by smartphone.
- [**131**星][5y] [Py] [ricterz/websocket-injection](https://github.com/ricterz/websocket-injection) WebSocket 中转注入工具
- [**127**星][18d] [Py] [mandatoryprogrammer/xsshunter_client](https://github.com/mandatoryprogrammer/xsshunter_client) Correlated injection proxy tool for XSS Hunter
- [**126**星][3y] [Batchfile] [3gstudent/clr-injection](https://github.com/3gstudent/clr-injection) Use CLR to inject all the .NET apps
- [**123**星][4m] [ObjC] [smilezxlee/zxhookdetection](https://github.com/smilezxlee/zxhookdetection) 【iOS应用安全】hook及越狱的基本防护与检测(动态库注入检测、hook检测与防护、越狱检测、签名校验、IDA反编译分析加密协议示例)
- [**118**星][2y] [C#] [malcomvetter/managedinjection](https://github.com/malcomvetter/managedinjection) A proof of concept for dynamically loading .net assemblies at runtime with only a minimal convention pre-knowledge
- [**117**星][5m] [C#] [gaprogman/owaspheaders.core](https://github.com/gaprogman/owaspheaders.core) A .NET Core middleware for injecting the Owasp recommended HTTP Headers for increased security
- [**117**星][2m] [C++] [praetorian-code/vulcan](https://github.com/praetorian-code/vulcan) a tool to make it easy and fast to test various forms of injection
- [**114**星][2m] [Ruby] [spiderlabs/beef_injection_framework](https://github.com/spiderlabs/beef_injection_framework) Inject beef hooks into HTTP traffic and track hooked systems from cmdline
- [**113**星][3y] [PS] [vletoux/ntlminjector](https://github.com/vletoux/ntlminjector) In case you didn't now how to restore the user password after a password reset (get the previous hash with DCSync)
- [**112**星][2y] [cujanovic/crlf-injection-payloads](https://github.com/cujanovic/crlf-injection-payloads) Payloads for CRLF Injection
- [**111**星][14d] [C++] [haram/splendid_implanter](https://github.com/haram/splendid_implanter) BattlEye compatible injector, done completely from user-mode, project by secret.club
- [**107**星][27d] [C] [yurushao/droid_injectso](https://github.com/yurushao/droid_injectso) A shared libraries injection tool.
- [**106**星][4y] [Eagle] [zapta/linbus](https://github.com/zapta/linbus) An Arduino based LINBUS stack and signal interceptor/injector.
- [**105**星][3y] [C++] [azuregreen/injectcollection](https://github.com/azuregreen/injectcollection) A collection of injection via vc++ in ring3
- [**104**星][4y] [Makefile] [dtrukr/flex_injected](https://github.com/dtrukr/flex_injected) Injecting FLEX with MobileSubstrate. Inject FLEX library into 3rd party apps.
- [**104**星][14d] [Py] [tintinweb/electron-inject](https://github.com/tintinweb/electron-inject) Inject javascript into closed source electron applications e.g. to enable developer tools for debugging.
- [**102**星][14d] [C++] [whid-injector/whid-31337](https://github.com/whid-injector/whid-31337) WHID Elite is a GSM-enabled Open-Source Multi-Purpose Offensive Device that allows a threat actor to remotely inject keystrokes, bypass air-gapped systems, conduct mousejacking attacks, do acoustic surveillance, RF replay attacks and much more. In practice, is THE Wet Dream of any Security Consultant out there!
- [**93**星][16d] [Py] [pdjstone/wsuspect-proxy](https://github.com/pdjstone/wsuspect-proxy) Python tool to inject fake updates into unencrypted WSUS traffic
- [**92**星][2y] [C] [3gstudent/inject-dll-by-process-doppelganging](https://github.com/3gstudent/inject-dll-by-process-doppelganging) Process Doppelgänging
- [**89**星][1m] [C] [xpn/ssh-inject](https://github.com/xpn/ssh-inject) A ptrace POC by hooking SSH to reveal provided passwords
- [**87**星][10d] [Py] [helpsystems/wiwo](https://github.com/helpsystems/wiwo) wiwo is a distributed 802.11 monitoring and injecting system that was designed to be simple and scalable, in which all workers (nodes) can be managed by a Python framework.
- [**86**星][4m] [Java] [pwntester/dupekeyinjector](https://github.com/pwntester/dupekeyinjector) DupeKeyInjector
- [**86**星][9m] [Py] [safebreach-labs/bitsinject](https://github.com/safebreach-labs/bitsinject) A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service), allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
- [**83**星][1m] [Go] [binject/binjection](https://github.com/binject/binjection) Injects additional machine instructions into various binary formats.
- [**83**星][11d] [JS] [fastify/light-my-request](https://github.com/fastify/light-my-request) Fake HTTP injection library
- [**83**星][17d] [C] [oleavr/ios-inject-custom](https://github.com/oleavr/ios-inject-custom) (iOS) 使用Frida注入自定义Payload
- [**82**星][4m] [C++] [changeofpace/mouclassinputinjection](https://github.com/changeofpace/mouclassinputinjection) MouClassInputInjection implements a kernel interface for injecting mouse input data packets into the input data stream of HID USB mouse devices.
- [**78**星][2y] [C] [alex9191/kernel-dll-injector](https://github.com/alex9191/kernel-dll-injector) Kernel-Mode Driver that loads a dll into every new created process that loads kernel32.dll module
- [**78**星][3y] [C] [ernacktob/esp8266_wifi_raw](https://github.com/ernacktob/esp8266_wifi_raw) ESP8266 wifi packet injection and receiving experiment
- [**75**星][17d] [C] [liji32/mip](https://github.com/liji32/mip) MIP – macOS Injection Platform
- [**74**星][2y] [C++] [3gstudent/inject-dll-by-apc](https://github.com/3gstudent/inject-dll-by-apc) Asynchronous Procedure Calls
- [**72**星][2m] [C#] [komefai/ps4remoteplayinterceptor](https://github.com/komefai/ps4remoteplayinterceptor) A small .NET library to intercept and inject controls on PS4 Remote Play for Windows
- [**70**星][8m] [JS] [lfzark/cookie-injecting-tools](https://github.com/lfzark/cookie-injecting-tools) A chrome extension ,cookie injecting tool includeing injecting ,editing ,adding ,removeing cookies.
- [**68**星][21d] [bastilleresearch/keyjack](https://github.com/bastilleresearch/keyjack) Device discovery tools and encrypted keystroke injection advisories for Logitech, Dell, Lenovo and AmazonBasics
- [**67**星][2m] [C] [merlijnwajer/tracy](https://github.com/merlijnwajer/tracy) tracy - a system call tracer and injector. Find us in #tracy on irc.freenode.net
- [**66**星][4m] [YARA] [fuzzysecurity/bluehatil-2020](https://github.com/fuzzysecurity/bluehatil-2020) BlueHatIL 2020 - Staying # and Bringing Covert Injection Tradecraft to .NET
- [**64**星][4m] [C++] [changeofpace/mouhidinputhook](https://github.com/changeofpace/mouhidinputhook) MouHidInputHook enables users to filter, modify, and inject mouse input data packets into the input data stream of HID USB mouse devices without modifying the mouse device stacks.
- [**62**星][8m] [C] [gdbinit/osx_boubou](https://github.com/gdbinit/osx_boubou) A PoC Mach-O infector via library injection
- [**62**星][2m] [Py] [feexd/vbg](https://github.com/feexd/vbg) 使用X11转发的SSH会话远程在客户端执行指令
- [**61**星][11d] [JS] [tserkov/vue-plugin-load-script](https://github.com/tserkov/vue-plugin-load-script) A Vue plugin for injecting remote scripts.
- [**58**星][12d] [Py] [adhorn/aws-chaos-scripts](https://github.com/adhorn/aws-chaos-scripts) Collection of python scripts to run failure injection on AWS infrastructure
- [**57**星][5y] [C++] [scadacs/plcinject](https://github.com/scadacs/plcinject) 
- [**57**星][3m] [C] [jar-o/osxinj_tut](https://github.com/jar-o/osxinj_tut) OSX injection tutorial: Hello World
- [**56**星][3y] [C++] [mq1n/dllthreadinjectiondetector](https://github.com/mq1n/dllthreadinjectiondetector) 
- [**56**星][2m] [HTML] [webcoding/js_block](https://github.com/webcoding/js_block) 研究学习各种拦截：反爬虫、拦截ad、防广告注入、斗黄牛等
- [**53**星][1m] [C++] [vmcall/eye_mapper](https://github.com/vmcall/eye_mapper) BattlEye x64 usermode injector
- [**52**星][4m] [Go] [stakater/proxyinjector](https://github.com/stakater/proxyinjector) A Kubernetes controller to inject an authentication proxy container to relevant pods - [✩Star] if you're using it!
- [**52**星][29d] [C] [pwn20wndstuff/injector](https://github.com/pwn20wndstuff/injector) 
- [**51**星][4m] [C++] [anubisss/szimatszatyor](https://github.com/anubisss/szimatszatyor) World of Warcraft (WoW): SzimatSzatyor is an injector sniffer written in C++
- [**51**星][4y] [C++] [uitra/injectora](https://github.com/uitra/injectora) x86/x64 manual mapping injector using the JUCE library
- [**51**星][7m] [ObjC] [kpwn/inj](https://github.com/kpwn/inj) task_for_pid injection that doesn't suck
- [**50**星][9y] [Perl] [spiderlabs/thicknet](https://github.com/spiderlabs/thicknet) TCP session interception and injection framework
- [**49**星][3m] [JS] [pownjs/pown-duct](https://github.com/pownjs/pown-duct) Essential tool for finding blind injection attacks.
- [**48**星][14d] [Py] [nickstadb/patch-apk](https://github.com/nickstadb/patch-apk) Wrapper to inject an Objection/Frida gadget into an APK, with support for app bundles/split APKs.
- [**47**星][3y] [Shell] [leanvel/iinject](https://github.com/leanvel/iinject) Tool to automate the process of embedding dynamic libraries into iOS applications from GNU/Linux
- [**47**星][11d] [Py] [adhorn/aws-lambda-chaos-injection](https://github.com/adhorn/aws-lambda-chaos-injection) Chaos Injection library for AWS Lambda
- [**46**星][1m] [C] [gdbinit/gimmedebugah](https://github.com/gdbinit/gimmedebugah) A small utility to inject a Info.plist into binaries.
- [**46**星][6m] [C] [cleric-k/flyskyrxfirmwarerssimod](https://github.com/cleric-k/flyskyrxfirmwarerssimod) Patched firmwares for the various FlySky receivers to inject RSSI in IBUS channel 14
- [**44**星][2y] [Py] [nullbites/snakeeater](https://github.com/nullbites/snakeeater) Python implementation of the reflective SO injection technique
- [**44**星][2m] [Py] [ledger-donjon/rainbow](https://github.com/ledger-donjon/rainbow) Makes Unicorn traces. Generic Side-Channel and Fault Injection simulator
- [**43**星][4m] [C#] [equifox/minjector](https://github.com/equifox/minjector) Mono Framework Injector (C#) using MInject Library
- [**43**星][4y] [C++] [sekoialab/binaryinjectionmitigation](https://github.com/sekoialab/binaryinjectionmitigation) Two tools used during our analysis of the Microsoft binary injection mitigation implemented in Edge TH2.
- [**42**星][4m] [Arduino] [exploitagency/github-esploit](https://github.com/exploitagency/github-esploit) !!! Deprecated See ESPloitV2 !!! Original PoC(Released: Sep 11, 2016) - WiFi controlled keystroke injection Using ESP8266 and 32u4 based Arduino HID Keyboard Emulator
- [**39**星][4m] [Py] [alttch/pptop](https://github.com/alttch/pptop) Open, extensible Python injector/profiler/analyzer
- [**38**星][10d] [C++] [ganyao114/sandboxhookplugin](https://github.com/ganyao114/sandboxhookplugin) demo for inject & hook in sandbox
- [**37**星][1m] [JS] [dangkyokhoang/man-in-the-middle](https://github.com/dangkyokhoang/man-in-the-middle) Modify requests, inject JavaScript and CSS into pages
- [**37**星][2m] [JS] [jackgu1988/dsploit-scripts](https://github.com/jackgu1988/dsploit-scripts) Scripts that could be injected in MITM attacks using dSploit
- [**36**星][2m] [C] [stealth/injectso](https://github.com/stealth/injectso) 
- [**35**星][2y] [Java] [minervalabsresearch/coffeeshot](https://github.com/minervalabsresearch/coffeeshot) CoffeeShot: Avoid Detection with Memory Injection
- [**35**星][24d] [Ruby] [skulltech/apk-payload-injector](https://github.com/skulltech/apk-payload-injector) POC for injecting Metasploit payloads on arbitrary APKs
- [**35**星][7m] [Py] [tidesec/tdscanner](https://github.com/tidesec/tdscanner) 自动化检测小工具，主要实现了域名枚举、链接爬取、注入检测、主机扫描、目录枚举、敏感信息检测等功能~
- [**34**星][6y] [osiris123/cdriver_loader](https://github.com/osiris123/cdriver_loader) Kernel mode driver loader, injecting into the windows kernel, Rootkit. Driver injections.
- [**34**星][1m] [Py] [rudsarkar/crlf-injector](https://github.com/rudsarkar/crlf-injector) A CRLF ( Carriage Return Line Feed ) Injection attack occurs when a user manages to submit a CRLF into an application. This is most commonly done by modifying an HTTP parameter or URL.
- [**33**星][19d] [JS] [ebay/userscript-proxy](https://github.com/ebay/userscript-proxy) HTTP proxy to inject scripts and stylesheets into existing sites.
- [**32**星][2m] [C++] [netdex/twinject](https://github.com/netdex/twinject) Automated player and hooking framework for bullet hell games from the Touhou Project
- [**31**星][23d] [C++] [amirrezanasiri/usb-keystroke-injector](https://github.com/amirrezanasiri/usb-keystroke-injector) 
- [**29**星][3y] [Assembly] [borjamerino/plcinjector](https://github.com/borjamerino/plcinjector) Modbus stager in assembly and some scripts to upload/download data to the holding register of a PLC
- [**29**星][18d] [C] [misje/dhcpoptinj](https://github.com/misje/dhcpoptinj) DHCP option injector
- [**27**星][4m] [Py] [fluxius/v2ginjector](https://github.com/fluxius/v2ginjector) V2GInjector - Tool to intrude a V2G PowerLine network, but also to capture and inject V2G packets
- [**27**星][3m] [Py] [xfkxfk/pyvulhunter](https://github.com/xfkxfk/pyvulhunter) python audit tool 审计 注入 inject
- [**25**星][9m] [Shell] [civisanalytics/iam-role-injector](https://github.com/civisanalytics/iam-role-injector) Assumes an IAM role via awscli STS call, injecting temporary credentials into shell environment
- [**25**星][5m] [C] [hatching/tracy](https://github.com/hatching/tracy) tracy - a system call tracer and injector. Find us in #tracy on irc.freenode.net
- [**25**星][9m] [JS] [sbarre/proxy-local-assets](https://github.com/sbarre/proxy-local-assets) BrowserSync-based Gulpfile to inject local development assets into a remote site
- [**24**星][2y] [retrogamer74/firmwarev5.05_mirahen_baseinjection](https://github.com/retrogamer74/firmwarev5.05_mirahen_baseinjection) Mira HEN 5.05 PS4 Fast developed firmware just for the basic injection
- [**23**星][1y] [JS] [0xsobky/xssbuster](https://github.com/0xsobky/xssbuster) XSSB is a proactive DOM sanitizer, defending against client-side injection attacks!
- [**23**星][1m] [C] [kismetwireless/lorcon](https://github.com/kismetwireless/lorcon) LORCON 802.11 Packet Injection Library (Mirror of Kismet repository)
- [**22**星][4m] [C++] [arsunt/tr2main](https://github.com/arsunt/tr2main) Tomb Raider II Injector Dynamic Library
- [**22**星][3y] [Cycript] [keith/injecturlprotocol](https://github.com/keith/injecturlprotocol) Inject a custom NSURLProtocl into a running application
- [**22**星][2y] [Py] [swisskyrepo/whid_toolkit](https://github.com/swisskyrepo/whid_toolkit) Simple script for the WHID injector - a rubberducky wifi
- [**21**星][4m] [Py] [bountystrike/injectus](https://github.com/bountystrike/injectus) CRLF and open redirect fuzzer
- [**20**星][1m] [Py] [migolovanov/libinjection-fuzzer](https://github.com/migolovanov/libinjection-fuzzer) This tool was written as PoC to article
- [**20**星][2m] [Smarty] [saltwaterc/aircrack-db](https://github.com/saltwaterc/aircrack-db) A list of wireless cards tested with the dual-card injection test and in the field
- [**19**星][1m] [Java] [toparvion/jmint](https://github.com/toparvion/jmint) jMint is a Side Effect Injection (SEI) tool aimed at simplicity of modifications expression
- [**17**星][2y] [Py] [mostafasoliman/cve-2017-6079-blind-command-injection-in-edgewater-edgemarc-devices-exploit](https://github.com/mostafasoliman/cve-2017-6079-blind-command-injection-in-edgewater-edgemarc-devices-exploit) 
- [**17**星][2y] [C] [paullj1/w-swfit](https://github.com/paullj1/w-swfit) x64 Windows Software Fault Injection Tool
- [**16**星][7y] [cccssw/jynkbeast](https://github.com/cccssw/jynkbeast) A novel rootkit under linux(test under cents 5.4) combine with preload_inject and sys_table modify
- [**16**星][12d] [JS] [freehuntx/frida-inject](https://github.com/freehuntx/frida-inject) This module allows you to easily inject javascript using frida and frida-load.
- [**15**星][17d] [Py] [ezelf/modbuskiller](https://github.com/ezelf/modbuskiller) [#Schneider] Dos PLC Modicon via Modbus Injection
- [**14**星][2y] [chango77747/shellcodeinjector_msbuild](https://github.com/chango77747/shellcodeinjector_msbuild) 
- [**13**星][1y] [JS] [lukaszmakuch/snabbdom-signature](https://github.com/lukaszmakuch/snabbdom-signature) Protects your app against vnode injection.
- [**13**星][2y] [C] [mnavaki/faros](https://github.com/mnavaki/faros) FAROS: Illuminating In-Memory Injection Attacks via Provenance-based Whole System Dynamic Information Flow Tracking
- [**12**星][3y] [C++] [wyexe/x64injector](https://github.com/wyexe/X64Injector) 
- [**12**星][4m] [Java] [orhun/apkservinject](https://github.com/orhun/apkservinject) Tool for injecting (smali) services to APK files
- [**11**星][7y] [Component Pascal] [dilshan/kidogo](https://github.com/dilshan/kidogo) Open Source USB Digital Signal Injector
- [**11**星][2m] [C] [resilar/psyscall](https://github.com/resilar/psyscall) Linux syscall() injection
- [**11**星][9m] [C] [wrenchonline/kernelapcinject](https://github.com/wrenchonline/kernelapcinject) 
- [**10**星][1y] [C#] [guitmz/msil-cecil-injection](https://github.com/guitmz/msil-cecil-injection) Injection of MSIL using Cecil
- [**10**星][26d] [C++] [hrt/mouseinjectdetection](https://github.com/hrt/mouseinjectdetection) Simple method of checking whether or not mouse movement or buttons (<windows 10) are injected
- [**10**星][3m] [C++] [jamesits/bgrtinjector](https://github.com/jamesits/bgrtinjector) Customize boot logo without modifying BIOS (UEFI firmware).
- [**9**星][16d] [JS] [davuxcom/frida-scripts](https://github.com/davuxcom/frida-scripts) Inject JS and C# into Windows apps, call COM and WinRT APIs
- [**8**星][2y] [C++] [xiaobo93/unmodule_shellcode_inject](https://github.com/xiaobo93/unmodule_shellcode_inject) 无模块注入工程 VS2008
- [**8**星][7m] [JS] [omarkurt/ssjs](https://github.com/omarkurt/ssjs) SSJS Web Shell Injection Case
- [**7**星][6m] [Shell] [enixes/injectorist](https://github.com/enixes/injectorist) A simple script to check all Wireless cards connected to your computer for Packet Injection capability
- [**7**星][2m] [C] [idigitalflame/inyourmems](https://github.com/idigitalflame/inyourmems) Windows Antivirus Evasion and Memory Injection
- [**7**星][2y] [CSS] [kp625544/runtime_secure](https://github.com/kp625544/runtime_secure) Injecting Security at run-time for web applications
- [**7**星][5m] [ObjC] [troyzhao/aanticrack](https://github.com/troyzhao/aanticrack) 注入与反注入工具 Disabled the injection defenses tool
- [**7**星][8m] [C] [anyfi/wperf](https://github.com/anyfi/wperf) 802.11 frame injection/reception tool for Linux mac80211 stack
- [**6**星][8y] [C++] [yifanlu/psxperia-wrapper](https://github.com/yifanlu/psxperia-wrapper) Loads injected PSX games on Xperia Play
- [**6**星][5y] [C] [mwwolters/dll-injection](https://github.com/mwwolters/DLL-Injection) 
- [**6**星][2y] [C] [moepinet/moepdefend](https://github.com/moepinet/moepdefend) Example monitoring/injection tool based on libmoep
- [**6**星][3y] [JS] [juzna/packet-injector](https://github.com/juzna/packet-injector) Packet analyzer and injector, written in JavaScript
- [**5**星][5m] [Java] [zabuzaw/mem-eater-bug](https://github.com/zabuzaw/mem-eater-bug) API that provides various methods for memory manipulation and injection using JNA.
- [**5**星][6m] [C++] [sh0/airown](https://github.com/sh0/airown) Packet injection tool
- [**4**星][4m] [C#] [mojtabatajik/.net-code-injector](https://github.com/mojtabatajik/.net-code-injector) Proof of concept of .Net worms
- [**3**星][1y] [JS] [mhelwig/wp-webshell-xss](https://github.com/mhelwig/wp-webshell-xss) A simple wordpress webshell injector
- [**3**星][7m] [C++] [sujuhu/antinject](https://github.com/sujuhu/antinject) 
- [**2**星][4y] [c++] [C4t0ps1s/injectme](https://bitbucket.org/c4t0ps1s/injectme) 
- [**2**星][6m] [Java] [conanjun/xssblindinjector](https://github.com/conanjun/xssblindinjector) burp插件，实现自动化xss盲打以及xss log
- [**2**星][2y] [JS] [mylesjohnson/pipe-injector](https://github.com/mylesjohnson/pipe-injector) Node.js script that can detect when "curl ... | bash" is being used and serve a different file than normal
- [**2**星][2y] [C] [neocui/uefi-var-in-disk](https://github.com/neocui/uefi-var-in-disk) Inject the UEFI variable in the first sector of hard disk
- [**2**星][2y] [C++] [wqqhit/dnshijack](https://github.com/wqqhit/dnshijack) A tool to poison a systems DNS cache by injecting faked DNS responses.
- [**2**星][2y] [JS] [xymostech/aphrodite-globals](https://github.com/xymostech/aphrodite-globals) A library for injecting global-scope styles using Aphrodite.
- [**2**星][4y] [C] [derosier/packetvector](https://github.com/derosier/packetvector) 802.11 management packet injection tool based on packetspammer
- [**2**星][2m] [C] [trustedsec/inproc_evade_get-injectedthread](https://github.com/trustedsec/inproc_evade_get-injectedthread) PoC code from blog
- [**1**星][2y] [C] [abapat/dnspoison](https://github.com/abapat/dnspoison) A DNS packet injection and poisoning detection utility
- [**1**星][8y] [C++] [iagox86/old-injector](https://github.com/iagox86/old-injector) 
- [**1**星][8m] [Go] [joanbono/pixload](https://github.com/joanbono/pixload) Image Payload Creating/Injecting tools
- [**1**星][3y] [C++] [bradleykirwan/disassociatedwifi](https://github.com/bradleykirwan/disassociatedwifi) A user space application for injecting packets into a WiFi interface in monitor mode.
- [**1**星][8y] [C] [iitis/iitis-generator](https://github.com/iitis/iitis-generator) Software for distributed statistical evaluation of IEEE 802.11 wireless networks using Linux mac80211 packet injection facility
- [**1**星][2y] [Py] [cardangi/xss-injector-python3-](https://github.com/cardangi/xss-injector-python3-) XSS PoC
- [**1**星][6m] [Py] [gunnargrosch/serverless-chaos-demo](https://github.com/gunnargrosch/serverless-chaos-demo) This example demonstrates how to use Adrian Hornsby's Failure Injection Layer (
- [**0**星][2y] [C] [brorica/http_inject](https://github.com/brorica/http_inject) 
- [**0**星][1y] [phuctam/server-side-template-injection-in-craftcms-](https://github.com/phuctam/server-side-template-injection-in-craftcms-) 
- [**0**星][4y] [Py] [dshtanger/zabbix_insertdb_injection_analy](https://github.com/dshtanger/zabbix_insertdb_injection_analy) 
- [**None**星][JS] [sajjadium/origintracer](https://github.com/sajjadium/origintracer) OriginTracer: An In-Browser System for Identifying Extension-based Ad Injection
- [**None**星][C] [kebugcheckex0xfffffff/kernel-dll-injector](https://github.com/kebugcheckex0xfffffff/kernel-dll-injector) Kernel-Mode Driver that loads a dll into every new created process that loads kernel32.dll module
- [**None**星][C++] [contionmig/millin-injector](https://github.com/contionmig/millin-injector) Millin Injector offers many features which can aid in creating usermode cheats. Its meant to be light weight and allow users to view things such as loaded modules, imports and other smaller things
- [**None**星][Java] [zabuzard/mem-eater-bug](https://github.com/zabuzard/mem-eater-bug) API that provides various methods for memory manipulation and injection using JNA.
- [**None**星][Py] [roottusk/xforwardy](https://github.com/roottusk/xforwardy) Host Header Injection Scanner
- [**None**星][C#] [thenameless314159/sockethook](https://github.com/thenameless314159/sockethook) Socket hook is an injector based on EasyHook which redirect the traffic to your local server.


***


## <a id="7004b87c5ab514b352dd7cc91acdd17b"></a>文章


- 2020.05 [netsparker] [Top 5 Most Dangerous Injection Attacks](https://www.netsparker.com/blog/web-security/top-dangerous-injection-attacks/)
- 2020.03 [rpis] [Injecting into 32-bit programs on macOS Mojave](https://rpis.ec/blog/mach_inject_32-writeup/)


# 贡献
内容为系统自动导出, 有任何问题请提issue
