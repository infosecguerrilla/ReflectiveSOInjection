# Reflective SO Injection

Reflective SO Injection was inspired by the concept of Reflective DLL Injection. It is virtually the same thing, but implemented to allow loading of SO (Shared Objects) on Linux. Currently only x86_64 is supported and it is only a prototype. The loader code was written by myself, but with the injection code I stole quite a bit of code from the linux-inject project since there is no sense in redoing what has already been done.

If you are interested in reading more about how this works please read the following blog post
https://infosecguerrilla.wordpress.com/2016/07/21/reflective-so-injection/

Known Issues

1. SELinux can prevent creation of a RWX mapping in target process causing loader to fail.

Tested on
* Ubuntu 14.04 x86_64
* Debian 8 x86_64
* Centos 6.8 x86_64
