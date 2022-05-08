#!/usr/bin/python
#-*- coding:utf-8 -*-

import pdb

import os
import sys
import base64
import binascii
import re

import tkinter
import tkinter.messagebox

from tkinter import *
import hashlib
import time

import sm
import cryptography.hazmat.backends.openssl.backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import ctypes
from ctypes import cdll, cast, pointer,create_string_buffer
from ctypes import c_int, c_ulong, c_char_p,c_ubyte,c_void_p

def load_smlib():
    dl = ctypes.cdll.LoadLibrary
    #lib = dl("./smlib.so") 
    lib = dl("./sm_lib.dll") 
    return lib


def version():
    tkinter.messagebox.showinfo('版本','V1.0.1\r\n '
                                + '1. 支持字符串，base64，hexstring之间转换；\r\n '
                                + '2. 支持十六进制不同格式与base64之间的转换；\r\n '
                                + '3. 支持MD5，SHA1，sha256功能；\r\n '
                                + '4. 支持国密SM3摘要运算；\r\n '
                                + '5. 支持RSA密钥PKCS#1 和 PKCS#8 相互转换； \r\n'
                                + '6. 支持HMAC运算(MD5/SHA1/SHA256/SM3); \r\n'
                                + '7. 支持HKDF密钥分散. \r\n')

def about():
    tkinter.messagebox.showinfo('关于','本软件由OneOs安全组自主设计研发，版权所有归OneOs安全组，如有疑问，可联系huzhongwen@cmiot.chinamobile.com')
    
def strhextob64(inputs):
    tmp = binascii.a2b_hex(inputs)
    result = str(base64.b64encode(tmp),'utf-8')
    return result

def strhextobytes(inputs):
    result = binascii.a2b_hex(inputs)
    return result

def bytestostrhex(inputs):
    return binascii.b2a_hex(inputs).decode('utf-8')

def bytestob64(inputs):
    #tmp = binascii.b2a_hex(inputs)
    #result = str(base64.b64encode(tmp),'utf-8')      #bytes to base64
    result = str(base64.b64encode(inputs),'utf-8')
    return result

def b64tobytes(inputs):
    tmp = bytes(base64.b64decode(inputs).hex(), encoding = "utf8")
    result = binascii.a2b_hex(tmp)
    return result

def b64tostrhex(inputs):
    temp = b64tobytes(inputs)
    result = bytestostrhex(temp)
    return result
    
def arraytohex(input, len):
    out = ''
    for i in range(len):
        out = out + bytestostrhex(input[i].to_bytes(length=1,byteorder='big'))
    return out

libobj = load_smlib()
LOG_LINE_NUM = 0
cur = "current"
last = "last"
class MY_GUI():
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name
        self.status_table = {cur: None,last: None}
        
        self.strexchgobj = StrExchangeWindow(self.init_window_name)
        self.dgtobj = DigestWindow(self.init_window_name)
        self.str2b64obj = String2HexWindow(self.init_window_name)
        self.rsakeyobj = RsaKeyWindow(self.init_window_name)
        self.hmacobj = HmacWindow(self.init_window_name)
        self.hkdfobj = KeyDerivationWindow(self.init_window_name)
        self.fsm_handle(self.strexchgobj)

    #设置窗口
    def set_init_window(self):
        #pdb.set_trace()
        self.init_window_name.title("密码计算辅助工具_v1.0 --OneOs安全组")           #窗口名
        #self.init_window_name.geometry('320x160+10+10')                         #290 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        self.init_window_name.geometry('1050x681+500+100')
        #self.init_window_name["bg"] = "pink"                                    #窗口背景色，其他背景色见：blog.csdn.net/chl0000/article/details/7657887
        #self.init_window_name.attributes("-alpha",0.9)                          #虚化，值越小虚化程度越高

        #菜单 -> 二级 摘要
        self.menue1 = Menu(self.init_window_name, tearoff=0)
        self.menue1.add_command(label="计算摘要", command=lambda: self.fsm_handle(self.dgtobj))
        self.menue1.add_separator()

        #菜单 -> 二级
        self.menue2 = Menu(self.init_window_name, tearoff=0)
        self.menue2.add_command(label="About", command=about)
        self.menue2.add_separator()
        self.menue2.add_command(label="Version", command=version)
        self.menue2.add_separator()
        #self.menue2.add_command(label="clear", command=hello)
        #self.menue2.add_separator()
        
        #菜单 -> 二级
        self.menue3 = Menu(self.init_window_name, tearoff=0)
        self.menue3.add_command(label="AES128")
        self.menue3.add_separator()
        self.menue3.add_command(label="SM4")
        self.menue3.add_separator()
        self.menue3.add_command(label="SM2")
        self.menue3.add_separator()

        #菜单 -> 二级
        self.menue4 = Menu(self.init_window_name, tearoff=0)
        self.menue4.add_command(label="hex <-> base64",command=lambda: self.fsm_handle(self.strexchgobj))
        self.menue4.add_separator()
        self.menue4.add_command(label="string <-> hex/base64",command=lambda: self.fsm_handle(self.str2b64obj))
        self.menue4.add_separator()

        #菜单 -> 二级
        self.menue5 = Menu(self.init_window_name, tearoff=0)
        self.menue5.add_command(label="Hmac",command=lambda: self.fsm_handle(self.hmacobj))
        self.menue5.add_separator()

        #菜单 -> 二级
        self.menue6 = Menu(self.init_window_name, tearoff=0)
        self.menue6.add_command(label="签名",command=lambda: self.fsm_handle(self.strexchgobj))
        self.menue6.add_separator()
        self.menue6.add_command(label="验签",command=lambda: self.fsm_handle(self.strexchgobj))
        self.menue6.add_separator()

        #菜单 -> 二级
        self.menue7 = Menu(self.init_window_name, tearoff=0)
        self.menue7.add_command(label="分散计算",command=lambda: self.fsm_handle(self.hkdfobj))
        self.menue7.add_separator()
        self.menue7.add_command(label="RSA密钥转换",command=lambda: self.fsm_handle(self.rsakeyobj))
        self.menue7.add_separator()
        
        #主菜单
        self.mebubar = Menu(self.init_window_name)
        
        self.mebubar.add_cascade(label="字符串", menu=self.menue4)
        self.mebubar.add_cascade(label="加密解密", menu=self.menue3)
        self.mebubar.add_cascade(label="签名验签", menu=self.menue6)
        self.mebubar.add_cascade(label="摘要", menu=self.menue1)
        self.mebubar.add_cascade(label="消息验证码", menu=self.menue5)
        self.mebubar.add_cascade(label="密钥处理", menu=self.menue7)
        self.mebubar.add_cascade(label="Help", menu=self.menue2) #原理：先在主菜单中添加一个菜单，与之前创建的菜单进行绑定。
        self.mebubar.add_command(label="退出", command=self.init_window_name.quit)

        self.init_window_name.config(menu=self.mebubar)

    def fsm_handle(self, currentobj):
        #pdb.set_trace()
        self.status_table[last] = self.status_table[cur]
        self.status_table[cur] = currentobj

        print("fsm handle",self.status_table[last]," --> ", self.status_table[cur])
        
        if(self.status_table[last]):
            self.status_table[last].remove_window()
        if(self.status_table[cur]):
            self.status_table[cur].create_window()

    #获取当前时间
    def get_current_time(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        return current_time


    #日志动态打印
    def write_log_to_Text(self,logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) +" " + str(logmsg) + "\n"      #换行
        if LOG_LINE_NUM <= 7:
            self.log_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_Text.delete(1.0,2.0)
            self.log_Text.insert(END, logmsg_in)

class DigestWindow(MY_GUI):
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name

    def create_window(self):
        #标签
        self.input_label = Label(self.init_window_name, text="待处理数据 (hex string eg. 00aabb) ")
        self.input_label.grid(row=0, column=0)
        self.result_label = Label(self.init_window_name, text="输出结果 (hex string eg. 00aabb) ")
        self.result_label.grid(row=0, column=12)
        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=12, column=0)
        
        #文本框
        self.input_Text = Text(self.init_window_name, width=67, height=35)  #原始数据录入框
        self.input_Text.grid(row=1, column=0, rowspan=10, columnspan=10)
        self.result_Text = Text(self.init_window_name, width=70, height=49)  #处理结果展示
        self.result_Text.grid(row=1, column=12, rowspan=15, columnspan=10)
        self.log_Text = Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_Text.grid(row=13, column=0, columnspan=10)
        
        #按钮
        self.str_trans_to_md5_button = Button(self.init_window_name, text="计算MD5", bg="lightblue", width=10,command=self.str_trans_to_md5)  # 调用内部方法  加()为直接调用
        self.str_trans_to_md5_button.grid(row=1, column=11)

        self.str_trans_to_sha1_button = Button(self.init_window_name, text="计算sha1", bg="lightblue", width=10,command=self.str_trans_to_sha1)  # 调用内部方法  加()为直接调用
        self.str_trans_to_sha1_button.grid(row=3, column=11)

        self.str_trans_to_sha256_button = Button(self.init_window_name, text="计算sha256", bg="lightblue", width=10,command=self.str_trans_to_sha256)  # 调用内部方法  加()为直接调用
        self.str_trans_to_sha256_button.grid(row=5, column=11)
        
        self.str_trans_to_sha512_button = Button(self.init_window_name, text="计算sha512", bg="lightblue", width=10,command=self.str_trans_to_sha512)  # 调用内部方法  加()为直接调用
        self.str_trans_to_sha512_button.grid(row=7, column=11)

        self.str_trans_to_sm3_button = Button(self.init_window_name, text="计算SM3", bg="lightblue", width=10,command=self.str_trans_to_sm3)  # 调用内部方法  加()为直接调用
        self.str_trans_to_sm3_button.grid(row=9, column=11)

        self.str_clear_button = Button(self.init_window_name, text="清除", bg="lightblue", width=10,command=self.clear_input_content)  
        self.str_clear_button.grid(row=11, column=11)

    def remove_window(self):
        #标签
        self.input_label.grid_remove()
        self.result_label.grid_remove()
        self.log_label.grid_remove()

        #文本框
        self.input_Text.grid_remove()
        self.result_Text.grid_remove()
        self.log_Text.grid_remove()

        #按钮
        self.str_trans_to_md5_button.grid_remove()
        self.str_trans_to_sha1_button.grid_remove()
        self.str_trans_to_sha256_button.grid_remove()
        self.str_trans_to_sha512_button.grid_remove()
        self.str_trans_to_sm3_button.grid_remove()
        self.str_clear_button.grid_remove()

    def clear_input_content(self):
        self.input_Text.delete(1.0,END)
        self.result_Text.delete(1.0,END)
        self.log_Text.delete(1.0,END)
            
    def str_trans_to_md5(self):
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        #print("src =",src)
        if src:
            try:
                myMd5 = hashlib.md5()
                myMd5.update(strhextobytes(str(src,encoding="utf-8")))
                myMd5_Digest = myMd5.hexdigest()
                #print(myMd5_Digest)
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,myMd5_Digest)
                self.write_log_to_Text("INFO:str_trans_to_md5 success")
            except:
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,"字符串转MD5失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_to_md5 failed")

    def str_trans_to_sha1(self):
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        #pdb.set_trace()
        if src:
            try:
                sha1 = hashlib.sha1()
                sha1.update(strhextobytes(str(src,encoding="utf-8")))
                sha1_Digest = sha1.hexdigest()
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,sha1_Digest)
                self.write_log_to_Text("INFO:str_trans_to_sha1 success")
            except:
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,"字符串转sha1失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_to_sha1 failed")

    def str_trans_to_sha256(self):
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        #pdb.set_trace()
        if src:
            try:
                sha256 = hashlib.sha256()
                sha256.update(strhextobytes(str(src,encoding="utf-8")))
                sha256_Digest = sha256.hexdigest()
                #print(myMd5_Digest)
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,sha256_Digest)
                self.write_log_to_Text("INFO:str_trans_to_sha256 success")
            except:
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,"字符串转sha256失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_to_sha256 failed")
            
    def str_trans_to_sha512(self):
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        #pdb.set_trace()
        if src:
            try:
                sha512 = hashlib.sha512()
                sha512.update(strhextobytes(str(src,encoding="utf-8")))
                sha512_Digest = sha512.hexdigest()
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,sha512_Digest)
                self.write_log_to_Text("INFO:str_trans_to_sha512 success")
            except:
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,"字符串转sha512失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_to_sha512 failed")

    def str_trans_to_sm3(self):
        #pdb.set_trace()
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        if src:
            try:
                sm3_Digest = sm.SM3.hash(strhextobytes(str(src,encoding="utf-8")))
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,bytestostrhex(sm3_Digest))
                self.write_log_to_Text("INFO:str_trans_to_sm3 success")
            except:
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,"字符串转sm3失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_to_sm3 failed")        

class StrExchangeWindow(MY_GUI):
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name
        
    def create_window(self):
        #标签
        self.input_label1 = Label(self.init_window_name, text="hex string (55aa66bb)", anchor='w')
        self.input_label1.grid(row=0, column=0)
        self.input_label2 = Label(self.init_window_name, text="hex bytes (55 aa 66 bb)", anchor='w')
        self.input_label2.grid(row=5, column=0)
        self.input_label3 = Label(self.init_window_name, text="hex array (0x55, 0xaa, 0x66, 0xbb)", anchor='w')
        self.input_label3.grid(row=10, column=0)
        self.input_label4 = Label(self.init_window_name, text="base64 (Vapmuw==)", anchor='w')
        self.input_label4.grid(row=15, column=0)

        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=30, column=0)

        #文本框
        self.input_Text1 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text1.grid(row=1, column=0, rowspan=2, columnspan=10)
        self.input_Text2 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text2.grid(row=6, column=0, rowspan=2, columnspan=10)
        self.input_Text3 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text3.grid(row=11, column=0, rowspan=2, columnspan=10)
        self.input_Text4 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text4.grid(row=16, column=0, rowspan=2, columnspan=10)

        self.log_Text = Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_Text.grid(row=31, column=0, columnspan=10)

        #按钮
        self.str_exchange_button = Button(self.init_window_name, text="一键转换", bg="lightblue", width=10,command=self.str_one_key_exchange)
        self.str_exchange_button.grid(row=10, column=15)


        self.str_clear_button = Button(self.init_window_name, text="清除", bg="lightblue", width=10,command=self.clear_input_content)  
        self.str_clear_button.grid(row=12, column=15)

    def remove_window(self):
        self.input_label1.grid_remove()
        self.input_label2.grid_remove()
        self.input_label3.grid_remove()
        self.input_label4.grid_remove()
        self.log_label.grid_remove()

        self.input_Text1.grid_remove()
        self.input_Text2.grid_remove()
        self.input_Text3.grid_remove()
        self.input_Text4.grid_remove()
        self.log_Text.grid_remove()

        self.str_exchange_button.grid_remove()
        self.str_clear_button.grid_remove()
        
    def clear_input_content(self):
        self.input_Text1.delete(1.0,END)
        self.input_Text2.delete(1.0,END)
        self.input_Text3.delete(1.0,END)
        self.input_Text4.delete(1.0,END)
        self.log_Text.delete(1.0,END)
        
    #功能函数
    def str_one_key_exchange(self):
        src1 = self.input_Text1.get(1.0,END).strip().replace("\n","").encode()
        src2 = self.input_Text2.get(1.0,END).strip().replace("\n","").encode()
        src3 = self.input_Text3.get(1.0,END).strip().replace("\n","").encode()
        src4 = self.input_Text4.get(1.0,END).strip().replace("\n","").encode()
        #pdb.set_trace()
        if src1:
            try:
                out1 = src1
                out2 = re.sub('([0-9a-fA-F]{2})', '\g<1> ', str(out1,encoding="utf-8"))
                out3 = re.sub('([0-9a-fA-F]{2})', '0x\g<1>, ', str(out1,encoding="utf-8"))[:-2]
                out4 = strhextob64(str(out1,encoding="utf-8"))

                #输出到界面
                self.input_Text2.delete(1.0,END)
                self.input_Text2.insert(1.0,bytes(out2, encoding="utf-8"))
                self.input_Text3.delete(1.0,END)
                self.input_Text3.insert(1.0,bytes(out3, encoding="utf-8"))
                self.input_Text4.delete(1.0,END)
                self.input_Text4.insert(1.0,bytes(out4, encoding="utf-8"))
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("hex string 转换失败")
                #log.log_exc()
        elif src2:
            try:
                out1 = str(src2,encoding="utf-8").replace(' ','')
                out2 = re.sub('([0-9a-fA-F]{2})', '\g<1> ', out1)
                out3 = re.sub('([0-9a-fA-F]{2})', '0x\g<1>, ', out1)[:-2]
                out4 = strhextob64(out1)

                #输出到界面
                self.input_Text1.delete(1.0,END)
                self.input_Text1.insert(1.0,bytes(out1, encoding="utf-8"))
                self.input_Text3.delete(1.0,END)
                self.input_Text3.insert(1.0,bytes(out3, encoding="utf-8"))
                self.input_Text4.delete(1.0,END)
                self.input_Text4.insert(1.0,bytes(out4, encoding="utf-8"))
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("hex string 转换失败")
                #log.log_exc()
        elif src3:
            try:
                tmp = str(src3,encoding="utf-8").replace(' ','').split(',')
                out1 = ""
                for i in tmp:
                    out1 = out1+i[2:]
                out2 = re.sub('([0-9a-fA-F]{2})', '\g<1> ', out1)
                out3 = re.sub('([0-9a-fA-F]{2})', '0x\g<1>, ', out1)
                out4 = strhextob64(out1)

                #输出到界面
                self.input_Text1.delete(1.0,END)
                self.input_Text1.insert(1.0,bytes(out1, encoding="utf-8"))
                self.input_Text2.delete(1.0,END)
                self.input_Text2.insert(1.0,bytes(out2, encoding="utf-8"))
                self.input_Text4.delete(1.0,END)
                self.input_Text4.insert(1.0,bytes(out4, encoding="utf-8"))
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("hex string 转换失败")
                #log.log_exc()
        elif src4:
            try:
                out1 = b64tostrhex(str(src4,encoding="utf-8").replace(' ',''))
                out2 = re.sub('([0-9a-fA-F]{2})', '\g<1> ', out1)
                out3 = re.sub('([0-9a-fA-F]{2})', '0x\g<1>, ', out1)[:-2]
                out4 = strhextob64(out1)

                #输出到界面
                self.input_Text1.delete(1.0,END)
                self.input_Text1.insert(1.0,bytes(out1, encoding="utf-8"))
                self.input_Text2.delete(1.0,END)
                self.input_Text2.insert(1.0,bytes(out2, encoding="utf-8"))
                self.input_Text3.delete(1.0,END)
                self.input_Text3.insert(1.0,bytes(out3, encoding="utf-8"))
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("hex string 转换失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:str_one_key_exchange failed")

class String2HexWindow(MY_GUI):
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name
        
    def create_window(self):
        #标签
        self.input_label1 = Label(self.init_window_name, text="string (你好)", anchor='w')
        self.input_label1.grid(row=0, column=0)
        self.input_label2 = Label(self.init_window_name, text="base64 (JXU0RjYwJXU1OTdE)", anchor='w')
        self.input_label2.grid(row=5, column=0)
        self.input_label3 = Label(self.init_window_name, text="hex string (257534463630257535393744)", anchor='w')
        self.input_label3.grid(row=10, column=0)

        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=30, column=0)

        #文本框
        self.input_Text1 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text1.grid(row=1, column=0, rowspan=2, columnspan=10)
        self.input_Text2 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text2.grid(row=6, column=0, rowspan=2, columnspan=10)
        self.input_Text3 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text3.grid(row=11, column=0, rowspan=2, columnspan=10)

        self.log_Text = Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_Text.grid(row=31, column=0, columnspan=10)

        #按钮
        self.str_exchange_button = Button(self.init_window_name, text="一键转换", bg="lightblue", width=10,command=self.str_one_key_exchange)
        self.str_exchange_button.grid(row=10, column=15)


        self.str_clear_button = Button(self.init_window_name, text="清除", bg="lightblue", width=10,command=self.clear_input_content)  
        self.str_clear_button.grid(row=12, column=15)

    def remove_window(self):
        self.input_label1.grid_remove()
        self.input_label2.grid_remove()
        self.input_label3.grid_remove()
        self.log_label.grid_remove()

        self.input_Text1.grid_remove()
        self.input_Text2.grid_remove()
        self.input_Text3.grid_remove()
        self.log_Text.grid_remove()

        self.str_exchange_button.grid_remove()
        self.str_clear_button.grid_remove()
        
    def clear_input_content(self):
        self.input_Text1.delete(1.0,END)
        self.input_Text2.delete(1.0,END)
        self.input_Text3.delete(1.0,END)
        self.log_Text.delete(1.0,END)
        
    #功能函数
    def str_one_key_exchange(self):
        src1 = self.input_Text1.get(1.0,END).strip().replace("\n","").encode()
        src2 = self.input_Text2.get(1.0,END).strip().replace("\n","").encode()
        src3 = self.input_Text3.get(1.0,END).strip().replace("\n","").encode()
        #pdb.set_trace()
        if src1:
            try:
                out1 = src1
                out2 = bytestob64(src1)
                out3 = bytestostrhex(src1)

                #输出到界面
                self.input_Text2.delete(1.0,END)
                self.input_Text2.insert(1.0,out2)
                self.input_Text3.delete(1.0,END)
                self.input_Text3.insert(1.0,out3)
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("hex string 转换失败")
                #log.log_exc()
        elif src2:
            try:
                out1 = str(b64tobytes(src2),encoding="utf-8")
                out2 = src2
                out3 = b64tostrhex(src2)

                #输出到界面
                self.input_Text1.delete(1.0,END)
                self.input_Text1.insert(1.0,out1)
                self.input_Text3.delete(1.0,END)
                self.input_Text3.insert(1.0,out3)
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("hex string 转换失败")
                #log.log_exc()
        elif src3:
            try:
                out1 = strhextobytes(str(src3,encoding="utf-8"))
                out2 = strhextob64(str(src3,encoding="utf-8"))
                out3 = src3

                #输出到界面
                self.input_Text1.delete(1.0,END)
                self.input_Text1.insert(1.0,out1)
                self.input_Text2.delete(1.0,END)
                self.input_Text2.insert(1.0,out2)
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("hex string 转换失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:str_one_key_exchange failed")


class RsaKeyWindow(MY_GUI):
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name

    def create_window(self):
        #标签
        self.input_label = Label(self.init_window_name, text="(RSA PKCS#1 密钥) ")
        self.input_label.grid(row=0, column=0)
        self.result_label = Label(self.init_window_name, text="(RSA PKCS#8 密钥) ")
        self.result_label.grid(row=0, column=12)
        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=12, column=0)
        
        #文本框
        self.input_Text = Text(self.init_window_name, width=67, height=35)  #原始数据录入框
        self.input_Text.grid(row=1, column=0, rowspan=10, columnspan=10)
        self.result_Text = Text(self.init_window_name, width=70, height=49)  #处理结果展示
        self.result_Text.grid(row=1, column=12, rowspan=15, columnspan=10)
        self.log_Text = Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_Text.grid(row=13, column=0, columnspan=10)
        
        #按钮
        self.pub_p1top8_button = Button(self.init_window_name, text="公钥\nP1 -> P8", bg="lightblue", width=10,command=self.pub_pkcs1topkcs8)  # 调用内部方法  加()为直接调用
        self.pub_p1top8_button.grid(row=1, column=11)

        self.pub_p8top1_button = Button(self.init_window_name, text="公钥\rP1 <- P8", bg="lightblue", width=10,command=self.pub_pkcs8topkcs1)  # 调用内部方法  加()为直接调用
        self.pub_p8top1_button.grid(row=2, column=11)

        self.pri_p1top8_button = Button(self.init_window_name, text="私钥\nP1 -> P8", bg="lightblue", width=10,command=self.pri_pkcs1topkcs8)  # 调用内部方法  加()为直接调用
        self.pri_p1top8_button.grid(row=5, column=11)

        self.pri_p8top1_button = Button(self.init_window_name, text="私钥\nP1 <- P8", bg="lightblue", width=10,command=self.pri_pkcs8topkcs1)  # 调用内部方法  加()为直接调用
        self.pri_p8top1_button.grid(row=6, column=11)

        self.str_clear_button = Button(self.init_window_name, text="清除", bg="lightblue", width=10,command=self.clear_input_content)  
        self.str_clear_button.grid(row=11, column=11)

    def remove_window(self):
        #标签
        self.input_label.grid_remove()
        self.result_label.grid_remove()
        self.log_label.grid_remove()

        #文本框
        self.input_Text.grid_remove()
        self.result_Text.grid_remove()
        self.log_Text.grid_remove()

        #按钮
        self.pub_p1top8_button.grid_remove()
        self.pub_p8top1_button.grid_remove()
        self.pri_p1top8_button.grid_remove()
        self.pri_p8top1_button.grid_remove()
        self.str_clear_button.grid_remove()

    def clear_input_content(self):
        self.input_Text.delete(1.0,END)
        self.result_Text.delete(1.0,END)
        self.log_Text.delete(1.0,END)
            
    def pub_pkcs1topkcs8(self):
        #pdb.set_trace()
        src1 = self.input_Text.get(1.0,END).encode()
        if src1:
            try:
                public_key = serialization.load_pem_public_key(
                  src1,
                  #rsa_pub_key,
                  backend=default_backend()
                  )
        
                #format public key to pkcs8
                pem = public_key.public_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.SubjectPublicKeyInfo     #p8 format
                          )
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,pem)
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("转换失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:pub_pkcs1topkcs8 failed")

    def pub_pkcs8topkcs1(self):
        src1 = self.result_Text.get(1.0,END).encode()
        if src1:
            try:
                public_key = serialization.load_pem_public_key(
                  src1,
                  #rsa_pub_key,
                  backend=default_backend()
                  )

                #format public key to pkcs1
                pem = public_key.public_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.PKCS1            #p1 format
                          )
                #输出到界面
                self.input_Text.delete(1.0,END)
                self.input_Text.insert(1.0,pem)
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("转换失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:pub_pkcs8topkcs1 failed")

    def pri_pkcs1topkcs8(self):
        src1 = self.input_Text.get(1.0,END).encode()
        if src1:
            try:
                private_key = serialization.load_pem_private_key(
                  src1,
                  #tmp,
                  password=None,
                  backend=default_backend()
                  )
                #format to pkcs8          
                pem = private_key.private_bytes(
                          encoding=serialization.Encoding.PEM,
                          format=serialization.PrivateFormat.PKCS8,
                          encryption_algorithm=serialization.NoEncryption()
                          )
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0,pem)
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("转换失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:pri_pkcs1topkcs8 failed")

    def pri_pkcs8topkcs1(self):
        #pdb.set_trace()
        src1 = self.result_Text.get(1.0,END).encode()
        if src1:
            try:
                private_key = serialization.load_pem_private_key(
                  src1,
                  #tmp,
                  password=None,
                  backend=default_backend()
                  )
                #format to pkcs8          
                pem = private_key.private_bytes(
                          encoding=serialization.Encoding.PEM,
                          format=serialization.PrivateFormat.TraditionalOpenSSL,
                          encryption_algorithm=serialization.NoEncryption()
                          )
                #输出到界面
                self.input_Text.delete(1.0,END)
                self.input_Text.insert(1.0,pem)
                
                self.write_log_to_Text("INFO:转换 success")
            except:
                self.write_log_to_Text("转换失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:pri_pkcs8topkcs1 failed")


class HmacWindow(MY_GUI):
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name

    def create_window(self):
        #标签
        self.input_label = Label(self.init_window_name, text="原文数据")
        self.input_label.grid(row=0, column=0)
        self.result_label = Label(self.init_window_name, text="Hmac结果")
        self.result_label.grid(row=0, column=23)
        self.key_label = Label(self.init_window_name, text="KEY(Hex)")
        self.key_label.grid(row=12, column=0)
        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=12, column=23)
        
        #文本框
        self.input_Text = Text(self.init_window_name, width=68, height=35)  #原始数据录入框
        self.input_Text.grid(row=1, column=0, rowspan=10, columnspan=10)
        self.result_Text = Text(self.init_window_name, width=69, height=35)  #处理结果展示
        self.result_Text.grid(row=1, column=23, rowspan=10, columnspan=10)
        self.key_Text = Text(self.init_window_name, width=68, height=9)  # 日志框
        self.key_Text.grid(row=13, column=0, columnspan=10)
        self.log_Text = Text(self.init_window_name, width=69, height=9)  # 日志框
        self.log_Text.grid(row=13, column=23, columnspan=10)
        
        #按钮
        self.md5_button = Button(self.init_window_name, text="Hmac-md5", bg="lightblue", width=10,command=self.calc_hamc_md5)  # 调用内部方法  加()为直接调用
        self.md5_button.grid(row=1, column=13)

        self.sha1_button = Button(self.init_window_name, text="Hmac-sha1", bg="lightblue", width=10,command=self.calc_hamc_sha1)  # 调用内部方法  加()为直接调用
        self.sha1_button.grid(row=3, column=13)

        self.sha256_button = Button(self.init_window_name, text="Hmac-sha256", bg="lightblue", width=10,command=self.calc_hamc_sha256)  # 调用内部方法  加()为直接调用
        self.sha256_button.grid(row=5, column=13)

        self.sm3_button = Button(self.init_window_name, text="Hmac-sm3", bg="lightblue", width=10,command=self.calc_hamc_sm3)  # 调用内部方法  加()为直接调用
        self.sm3_button.grid(row=7, column=13)

        self.str_clear_button = Button(self.init_window_name, text="清除", bg="lightblue", width=10,command=self.clear_input_content)  
        self.str_clear_button.grid(row=11, column=13)

    def remove_window(self):
        #标签
        self.input_label.grid_remove()
        self.result_label.grid_remove()
        self.log_label.grid_remove()
        self.key_label.grid_remove()
        
        #文本框
        self.input_Text.grid_remove()
        self.result_Text.grid_remove()
        self.key_Text.grid_remove()
        self.log_Text.grid_remove()

        #按钮
        self.md5_button.grid_remove()
        self.sha1_button.grid_remove()
        self.sha256_button.grid_remove()
        self.sm3_button.grid_remove()
        self.str_clear_button.grid_remove()

    def clear_input_content(self):
        self.input_Text.delete(1.0,END)
        self.result_Text.delete(1.0,END)
        self.key_Text.delete(1.0,END)
        self.log_Text.delete(1.0,END)
            
    def calc_hamc_md5(self):
        #pdb.set_trace()
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        key = self.key_Text.get(1.0,END).strip().replace("\n","").encode()
        if src:
            try:
                mac = hmac.HMAC(strhextobytes(str(key,encoding="utf-8")), hashes.MD5(),          #取共享密钥的后16字节，作为HMAC的MK
                        backend=default_backend())
                mac.update(strhextobytes(str(src,encoding="utf-8")))
                ciphermac = mac.finalize()
                
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0, bytestostrhex(ciphermac))
                
                self.write_log_to_Text("INFO:运算 success")
            except:
                self.write_log_to_Text("运算失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:calc_hamc_md5 failed")

    def calc_hamc_sha1(self):
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        key = self.key_Text.get(1.0,END).strip().replace("\n","").encode()
        if src:
            try:
                mac = hmac.HMAC(strhextobytes(str(key,encoding="utf-8")), hashes.SHA1(),          #取共享密钥的后16字节，作为HMAC的MK
                        backend=default_backend())
                mac.update(strhextobytes(str(src,encoding="utf-8")))
                ciphermac = mac.finalize()
                
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0, bytestostrhex(ciphermac))
                
                self.write_log_to_Text("INFO:运算 success")
            except:
                self.write_log_to_Text("运算失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:calc_hamc_sha1 failed")

    def calc_hamc_sha256(self):
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        key = self.key_Text.get(1.0,END).strip().replace("\n","").encode()
        if src:
            try:
                mac = hmac.HMAC(strhextobytes(str(key,encoding="utf-8")), hashes.SHA256(),          #取共享密钥的后16字节，作为HMAC的MK
                        backend=default_backend())
                mac.update(strhextobytes(str(src,encoding="utf-8")))
                ciphermac = mac.finalize()
                
                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0, bytestostrhex(ciphermac))
                
                self.write_log_to_Text("INFO:运算 success")
            except:
                self.write_log_to_Text("运算失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:calc_hamc_sha256 failed")

    def calc_hamc_sm3(self):
        #pdb.set_trace()
        src = self.input_Text.get(1.0,END).strip().replace("\n","").encode()
        key = self.key_Text.get(1.0,END).strip().replace("\n","").encode()
        if src:
            try:
                libobj.OSR_SM3_HMAC.argtypes  = [c_void_p, c_int, c_void_p, c_int, c_void_p]
                libobj.OSR_SM3_HMAC.restype = c_int
                bkey = strhextobytes(str(key,encoding="utf-8"))
                bmsg = strhextobytes(str(src,encoding="utf-8"))
                key = create_string_buffer(bkey)
                message = create_string_buffer(bmsg)
                mac = (c_ubyte * 32)()
                ret = libobj.OSR_SM3_HMAC(key, len(bkey), message, len(bmsg), mac)

                #输出到界面
                self.result_Text.delete(1.0,END)
                self.result_Text.insert(1.0, arraytohex(mac, len(mac)))
                
                self.write_log_to_Text("INFO:运算 success")
            except:
                self.write_log_to_Text("运算失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:calc_hamc_sm3 failed")

class KeyDerivationWindow(MY_GUI):
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name
        
    def create_window(self):
        #标签
        self.input_label1 = Label(self.init_window_name, text="Master key (257534463630257535393744)", anchor='w')
        self.input_label1.grid(row=0, column=0)
        self.input_label2 = Label(self.init_window_name, text="Salt (257534463630257535393744)", anchor='w')
        self.input_label2.grid(row=5, column=0)
        self.input_label3 = Label(self.init_window_name, text="Output Key (257534463630257535393744)", anchor='w')
        self.input_label3.grid(row=10, column=0)

        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=30, column=0)

        #文本框
        self.input_Text1 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text1.grid(row=1, column=0, rowspan=2, columnspan=10)
        self.input_Text2 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text2.grid(row=6, column=0, rowspan=2, columnspan=10)
        self.input_Text3 = Text(self.init_window_name, width=67, height=4)  
        self.input_Text3.grid(row=11, column=0, rowspan=2, columnspan=10)

        self.log_Text = Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_Text.grid(row=31, column=0, columnspan=10)

        #按钮
        self.str_exchange_button = Button(self.init_window_name, text="HKDF", bg="lightblue", width=10,command=self.calc_hkdf)
        self.str_exchange_button.grid(row=10, column=15)


        self.str_clear_button = Button(self.init_window_name, text="清除", bg="lightblue", width=10,command=self.clear_input_content)  
        self.str_clear_button.grid(row=12, column=15)

    def remove_window(self):
        self.input_label1.grid_remove()
        self.input_label2.grid_remove()
        self.input_label3.grid_remove()
        self.log_label.grid_remove()

        self.input_Text1.grid_remove()
        self.input_Text2.grid_remove()
        self.input_Text3.grid_remove()
        self.log_Text.grid_remove()

        self.str_exchange_button.grid_remove()
        self.str_clear_button.grid_remove()
        
    def clear_input_content(self):
        self.input_Text1.delete(1.0,END)
        self.input_Text2.delete(1.0,END)
        self.input_Text3.delete(1.0,END)
        self.log_Text.delete(1.0,END)
        
    #功能函数
    def calc_hkdf(self):
        #pdb.set_trace()
        masterkey = self.input_Text1.get(1.0,END).strip().replace("\n","").encode()
        in_salt = self.input_Text2.get(1.0,END).strip().replace("\n","").encode()
        #pdb.set_trace()
        if masterkey and in_salt:
            try:
                derived_key = HKDF(
                        algorithm=hashes.SHA256(), length=16, salt=strhextobytes(str(in_salt,encoding="utf-8")),                
                        info=b'', backend=default_backend()).derive(strhextobytes(str(masterkey,encoding="utf-8")))

                #输出到界面
                self.input_Text3.delete(1.0,END)
                self.input_Text3.insert(1.0,bytestostrhex(derived_key))
                
                self.write_log_to_Text("INFO:运算 success")
            except:
                self.write_log_to_Text("运算失败")
                #log.log_exc()
        else:
            self.write_log_to_Text("ERROR:calc_hkdf failed")

def gui_start():
    init_window = Tk()              #实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()

    init_window.mainloop()          #父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示


gui_start()


