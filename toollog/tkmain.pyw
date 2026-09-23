import os
import time
import string
import tkinter
import tkinter.colorchooser
import tkinter.filedialog
import tkinter.messagebox
import tkinter.scrolledtext
import tkinter.simpledialog
from unittest.mock import ANY

import depressor.decode_noncrypt as dtool

# 创建应用程序窗口
app = tkinter.Tk()
app.title('DepressLog')
# app.pack_propagate(False) # 关闭自动收缩，pack布局用
# app['width'] = 800
# app['height'] = 600
app.geometry('800x600')

RET_OK = 0
RET_FAIL = -1
# 当前文件名

logText = ANY
srcVar = ANY
destVar = ANY

def append_log(msg: str):
    # time = timeer()
    # 1. 解锁，允许修改
    logText.config(state="normal")
    # 2. 在末尾插入文本，tk.END 代表文本最后位置
    logText.insert(tkinter.END, msg + '\n')
    # 3. 自动滚动到底部，直接看到最新日志
    logText.see(tkinter.END)
    # 4. 重新锁定为只读
    logText.config(state="disabled")
    print(msg)

def pickup_log():
    # 如果内容已改变，先保存
    logFile = tkinter.filedialog.askopenfilename(title='Pick up file', filetypes=[('Log files', '*.xlog')])
    if logFile and os.path.isfile(logFile):
        # 清空内容,0.0是lineNumber.Column的表示方法
        return RET_OK, logFile
    else:
        msg = 'No file selected!'
        print(msg)
        return RET_FAIL, msg


# 包装回调函数，给Button使用
def on_pickup_click():
    global srcVar
    # 调用，拿到元组
    ret_code, ret_msg = pickup_log()
    mark = ''
    if ret_code == RET_OK:
        # 你可以在这里把路径赋值给变量，例如 srcVar.set(ret_msg)
        srcVar.set(ret_msg)
        mark = 'SUCCESS'
    else:
        srcVar.set('')
        mark = 'FALI'

    msg = f'pick up: {mark}[{ret_code}, {ret_msg}]'
    append_log(msg)



def choose_dest_dir():
    # 如果内容已改变，先保存
    dest_dir = tkinter.filedialog.askdirectory(title='Choose a Directory')
    if dest_dir and os.path.isdir(dest_dir):
        # 清空内容,0.0是lineNumber.Column的表示方法
        return RET_OK, dest_dir
    else:
        msg = 'No directory selected!'
        print(msg)
        return RET_FAIL, msg


def on_choose_dest_dir():
    global destVar
    # 调用，拿到元组
    ret_code, ret_msg = choose_dest_dir()
    if ret_code == RET_OK:
        destVar.set(ret_msg)
        mark = 'SUCCESS'
    else:
        tmp = srcVar.get()
        destVar.set(tmp)
        mark = f'Warning use [{tmp}]'
    msg = f'choose dir: {mark}[{ret_code}, {ret_msg}]'
    append_log(msg)

def depress_log():
    src = srcVar.get()
    dest = destVar.get()
    # 如果内容已改变，先保存
    if len(src) == 0:
        append_log('No file selected')
        files = []
    else:
        files = [f for f in src.split(',') if f.strip()]
    result = dtool.depress(files, dest, callback=append_log)
    append_log("====处理全部完成====")

def on_depress_log():
    # 如果内容已改变，先保存
    depress_log()

def UI():
    # lbSrc = tkinter.Label(app, text='Source:',
    #                           justify=tkinter.LEFT,
    #                           anchor = 'e',
    #                           width=80, height=48)
    # lbSrc.grid(row=0, column=0)
    # varSrc = tkinter.StringVar(app, value='')
    # entrySrc = tkinter.Entry(app,
    #                           width=80,
    #                           textvariable=varSrc)
    # entrySrc.grid(row=0, column=1)
    # entrySrc.place(x=100, y=5, width=80, height=20)
    #
    # destLB = tkinter.Label(app, text='Destination:',
    #                           justify=tkinter.RIGHT,
    #                           anchor = 'e',
    #                           width=80, height=48)
    # destLB.grid(row=2, column=0)
    # destVar = tkinter.StringVar(app, value='')
    # destEntry = tkinter.Entry(app,
    #                           width=120,
    #                           textvariable=destVar)
    # destEntry.grid(row=2, column=1)

    global logText, srcVar, destVar
    # ===== 第一个 Frame：登录模块 =====
    conf_frame = tkinter.Frame(app, bg="#e8e8e8", bd=1, relief=tkinter.RIDGE)
    conf_frame.pack(pady=10, padx=10, fill=tkinter.X)
    # 登录模块内的组件
    tkinter.Label(conf_frame, text="Source:", bg="#e8e8e8", width=10, anchor='e').grid(row=0, column=0, padx=5, pady=5)

    conf_frame.columnconfigure(1, weight=8)
    srcVar = tkinter.StringVar(app, value='')
    tkinter.Entry(conf_frame, textvariable=srcVar).grid(row=0, column=1, padx=5, pady=5, ipady=4, sticky="ew")
    conf_frame.columnconfigure(2, weight=1)
    tkinter.Button(conf_frame, text="Pick Up", command=on_pickup_click).grid(row=0, column=2, padx=10, pady=5,
                                                                             sticky="ew")

    tkinter.Label(conf_frame, text="Destination:", bg="#e8e8e8", width=10, anchor='e').grid(row=1, column=0, padx=5,
                                                                                            pady=5)
    destVar = tkinter.StringVar(app, value='')
    # conf_frame.columnconfigure(1, weight=8)
    tkinter.Entry(conf_frame, textvariable=destVar).grid(row=1, column=1, padx=5, pady=5, ipady=4, sticky='ew')
    # conf_frame.columnconfigure(2, weight=1)
    tkinter.Button(conf_frame, text="Choose",
                   command=on_choose_dest_dir
                   ).grid(row=1, column=2, padx=10, pady=5, sticky='ew')
    # tkinter.Button(conf_frame, text="登录").grid(row=0, column=2, rowspan=2, padx=10, pady=5)

    opt_frame = tkinter.Frame(app, bg="#e8e8e8", bd=1, relief=tkinter.SOLID)
    opt_frame.pack(pady=2, padx=10, fill=tkinter.X)
    tkinter.Button(opt_frame, text="Depress", anchor='center', width=10
                   , command=on_depress_log).grid(row=0, column=0, padx=10, pady=20)

    # buttonOk = tkinter.Button(app, text='open',
    #                           width=40, height=32,
    #                           activeforeground='#ff0000',  # 按下按钮时文字颜色
    #                           command=openlog)
    # buttonOk.place(x=30, y=100, width=50, height=20)
    log_frame = tkinter.LabelFrame(app, bg="#efefef", text='Result', bd=1, relief=tkinter.SOLID)
    log_frame.pack(pady=10, padx=10, fill=tkinter.X)
    log_frame.columnconfigure(0, weight=1)
    logText = tkinter.scrolledtext.ScrolledText(log_frame, height=20)
    logText.grid(row=0, column=0, padx=5, pady=5, ipady=4, sticky='ew')
    logText.config(state=tkinter.DISABLED)


UI()
app.mainloop()
