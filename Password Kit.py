# -*- coding: utf-8 -*-

import wx
import time
import base64
import sha
import sqlite3

class Securecode():
    def endecrypt(self, strs, key, isencrypt = False):
        if isencrypt:
            strs = strs.encode('utf-8')
        dynkey = sha.new(str(time.time())).hexdigest() if isencrypt else strs[0:40]
        dynkey = dynkey if isencrypt else dynkey[20:40] + dynkey[0:20]
        fixedkey = sha.new(key).hexdigest()
        dynkeypart1 = dynkey[0:20]
        dynkeypart2 = dynkey[20:]
        fixedketpt1 = fixedkey[0:20]
        fixedketpt2 = fixedkey[20:]
        newkey = sha.new(dynkeypart1 + fixedketpt1 + dynkeypart2 + fixedketpt2).hexdigest()
        if isencrypt:
            newstring = fixedketpt1 + strs + dynkeypart2
        else:
            newstring = base64.b64decode(strs[40:].replace('_', '='))
        result = ''
        for i in range(0, len(newstring)):
            j = i % 40
            result += chr(ord(newstring[i]) ^ ord(newkey[j]))
        dynkey = dynkey[20:40] + dynkey[0:20]
        return dynkey + base64.b64encode(result).replace('=', '_') if isencrypt else result[20:-20].decode('utf-8')

class Frame(wx.Frame):
    def __init__(self, **kwargs):
        title = kwargs['title'] if 'title' in kwargs else 'Password Kit V1.0 Alpha'
        parent = kwargs['parent'] if 'parent' in kwargs else None
        wx.Frame.__init__(self, parent, wx.ID_ANY, title)

class App(wx.App):
    def __init__(self, redirect = False):
        wx.App.__init__(self, redirect)

    def OnInit(self):
        self.secure = Securecode()
        self.key = "don't panic."
        self.font = wx.Font(12, wx.MODERN, wx.NORMAL, wx.NORMAL, False, u'Consolas')
        if self.__dbinit() == 1:
            self.welcome()
        else:
            self.auth()
        return True

    def welcome(self):
        self.welcomeframe = Frame(title = u'首次使用请设置安全密码')
        panel = wx.Panel(self.welcomeframe)
        sizer = wx.BoxSizer(wx.VERTICAL)
        lb_pwd = wx.StaticText(panel, wx.ID_ANY, u'密码:')
        self.te_pwd = wx.TextCtrl(panel, wx.ID_ANY, size = (215, 25), style = wx.TE_PASSWORD)
        self.te_pwd.SetFont(self.font)
        lb_cpwd = wx.StaticText(panel, wx.ID_ANY, u'确认密码:')
        self.te_cpwd = wx.TextCtrl(panel, wx.ID_ANY, size = (215, 25), style = wx.TE_PASSWORD)
        self.te_cpwd.SetFont(self.font)
        btn_submit = wx.Button(panel, wx.ID_ANY, u'确定')
        panel.Bind(wx.EVT_BUTTON, self.setpwdfirsttime, btn_submit)
        sizer.Add(lb_pwd, 0, wx.LEFT|wx.TOP|wx.RIGHT)
        sizer.Add(self.te_pwd, 0, wx.TOP|wx.RIGHT|wx.EXPAND)
        sizer.Add(lb_cpwd, 0, wx.LEFT|wx.RIGHT)
        sizer.Add(self.te_cpwd, 1, wx.RIGHT|wx.EXPAND)
        sizer.Add(btn_submit, 0, wx.CENTER)
        panel.SetSizer(sizer)
        sizer.Fit(self.welcomeframe)
        self.welcomeframe.Show()
        self.welcomeframe.Bind(wx.EVT_CLOSE, self.__exit, self.welcomeframe)

    def setpwdfirsttime(self, event):
        te_pwd = self.te_pwd.GetValue()
        te_cpwd = self.te_cpwd.GetValue()
        if te_pwd == '':
            dlg = wx.MessageDialog(self.welcomeframe, u'请输入密码', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        if len(te_pwd) < 6:
            dlg = wx.MessageDialog(self.welcomeframe, u'密码要大于等于6位哦', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        if te_pwd != te_cpwd:
            dlg = wx.MessageDialog(self.welcomeframe, u'密码和确认密码不一致', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        self.__cs.execute('create table pwk_secure (uid integer primary key autoincrement,pw text,create_data datetime)')
        self.__cs.execute("insert into pwk_secure values(null,'" + self.secure.endecrypt(te_pwd, self.key, True) + "','" + time.strftime('%Y-%m-%d %H:%M:%S') + "')")
        self.__conn.commit()
        self.welcomeframe.Destroy()
        self.key = "don't" + te_pwd + ' panic.'
        self.main()

    def auth(self):
        self.__cs.execute("select count(*) from sqlite_master where type='table' and name='pwk_secure'")
        count = self.__cs.fetchone()
        if count[0] == 0:
            self.welcome()
            return False
        self.welcomeframe = Frame(title = u'登录')
        panel = wx.Panel(self.welcomeframe)
        sizer = wx.BoxSizer(wx.VERTICAL)
        lb_pwd = wx.StaticText(panel, wx.ID_ANY, u'密码:')
        self.te_pwd = wx.TextCtrl(panel, wx.ID_ANY, size = (215, 25), style = wx.TE_PASSWORD)
        self.te_pwd.SetFont(self.font)
        btn_submit = wx.Button(panel, wx.ID_ANY, u'确定')
        panel.Bind(wx.EVT_BUTTON, self.verify, btn_submit)
        sizer.Add(lb_pwd, 0, wx.LEFT|wx.TOP|wx.RIGHT)
        sizer.Add(self.te_pwd, 0, wx.TOP|wx.RIGHT|wx.EXPAND)
        sizer.Add(btn_submit, 0, wx.CENTER)
        panel.SetSizer(sizer)
        sizer.Fit(self.welcomeframe)
        self.welcomeframe.Show()
        self.welcomeframe.Bind(wx.EVT_CLOSE, self.__exit, self.welcomeframe)

    def verify(self, event):
        te_pwd = self.te_pwd.GetValue()
        if te_pwd == '':
            dlg = wx.MessageDialog(self.welcomeframe, u'请输入密码', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        self.__cs.execute('select * from pwk_secure')
        data = self.__cs.fetchone()
        if te_pwd != self.secure.endecrypt(data[1], "don't panic."):
            self.te_pwd.SetValue('')
            dlg = wx.MessageDialog(self.welcomeframe, u'密码错误，请重试', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        self.welcomeframe.Destroy()
        self.key = "don't" + te_pwd + ' panic.'
        self.main()

    def main(self):
        self.frame = Frame()
        self.frame.CreateStatusBar()
        filemenu = wx.Menu()
        onfilemenuaddrecord = filemenu.Append(wx.ID_ANY, u'添加记录', u'新增加一条记录')
        filemenu.AppendSeparator()
        onfilemenuexit = filemenu.Append(wx.ID_EXIT, u'退出', u'退出程序')
        setupmenu = wx.Menu()
        onchangepwd = setupmenu.Append(wx.ID_ANY, u'修改密码', u'修改安全密码')
        helpmenu = wx.Menu()
        onhelpmenuabout = helpmenu.Append(wx.ID_ABOUT, u'关于', u'关于此程序')
        menubar = wx.MenuBar()
        menubar.Append(filemenu, u'文件')
        menubar.Append(setupmenu, u'设置')
        menubar.Append(helpmenu, u'帮助')
        self.frame.SetMenuBar(menubar)
        self.pwlistboard = wx.ListCtrl(self.frame, style = wx.LC_REPORT)
        self.pwlistboard.InsertColumn(0, 'ID', wx.LIST_FORMAT_CENTER, 47)
        self.pwlistboard.InsertColumn(1, u'记录名称', wx.LIST_FORMAT_CENTER, 248)
        self.pwlistboard.InsertColumn(2, u'最后修改', wx.LIST_FORMAT_CENTER, 147)
        self.frame.Bind(wx.EVT_MENU, self.onfilemenuaddrecord, onfilemenuaddrecord)
        self.frame.Bind(wx.EVT_MENU, self.__exit, onfilemenuexit)
        self.frame.Bind(wx.EVT_MENU, self.onchangepwd, onchangepwd)
        self.frame.Bind(wx.EVT_MENU, self.onhelpmenuabout, onhelpmenuabout)
        self.pwlistboard.Bind(wx.EVT_LIST_ITEM_SELECTED, self.onpwlistselected)
        self.pwlistboard.Bind(wx.EVT_CONTEXT_MENU, self.pwlistmenu)
        self.pwlistboard.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.onpopupedit)
        self.pwshowboard = wx.TextCtrl(self.frame, style = wx.TE_MULTILINE|wx.TE_READONLY)
        self.pwshowboard.SetFont(self.font)
        self.pwlistload()
        self.recordframeshow = False
        self.changepwdframeshow = False
        self.frame.Bind(wx.EVT_CLOSE, self.__exit, self.frame)
        self.sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.sizer.Add(self.pwlistboard, 1, wx.EXPAND)
        self.sizer.Add(self.pwshowboard, 1, wx.EXPAND)
        self.frame.SetSizer(self.sizer)
        self.sizer.Fit(self.frame)
        self.frame.SetSize((900, 500))
        self.frame.Show()

    def onfilemenuaddrecord(self, event):
        if self.recordframeshow:
            return False
        self.recordframe = Frame(title = u'添加记录')
        panel = wx.Panel(self.recordframe)
        sizer = wx.BoxSizer(wx.VERTICAL)
        lb_name = wx.StaticText(panel, wx.ID_ANY, u'名称:')
        self.te_name = wx.TextCtrl(panel, wx.ID_ANY, size = (400, -1))
        self.te_name.SetFont(self.font)
        lb_content = wx.StaticText(panel, wx.ID_ANY, u'内容:')
        self.te_content = wx.TextCtrl(panel, wx.ID_ANY, style = wx.TE_MULTILINE, size = (400, 300))
        self.te_content.SetFont(self.font)
        btn_submit = wx.Button(panel, wx.ID_ANY, u'确定')
        panel.Bind(wx.EVT_BUTTON, self.onaddrecordsubmit, btn_submit)
        sizer.Add(lb_name, 0, wx.LEFT|wx.TOP|wx.RIGHT)
        sizer.Add(self.te_name, 0, wx.TOP|wx.RIGHT|wx.EXPAND)
        sizer.Add(lb_content, 0, wx.LEFT|wx.RIGHT)
        sizer.Add(self.te_content, 1, wx.RIGHT|wx.EXPAND)
        sizer.Add(btn_submit, 0, wx.CENTER)
        panel.SetSizer(sizer)
        sizer.Fit(self.recordframe)
        self.recordframe.Show()
        self.recordframeshow = True
        self.recordframe.Bind(wx.EVT_CLOSE, self.__recordframeclose, self.recordframe)

    def updaterecordsubmit(self, event):
        te_name = self.te_name.GetValue()
        te_content = self.te_content.GetValue()
        if te_name == '':
            dlg = wx.MessageDialog(self.recordframe, u'请输入记录标题', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        if te_content == '':
            dlg = wx.MessageDialog(self.recordframe, u'请输入记录内容', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        self.__cs.execute("update pwk_data set name='" + self.secure.endecrypt(te_name, self.key, True) + "',content='" + self.secure.endecrypt(te_content, self.key, True) + "',last_modified='" + time.strftime('%Y-%m-%d %H:%M:%S') + "' where did=" + self.updatedid)
        self.__conn.commit()
        self.recordframe.Close()
        self.pwlistload()
        self.pwshowboard.SetValue(te_content)
        self.frame.SetStatusText(te_name)

    def onaddrecordsubmit(self, event):
        te_name = self.te_name.GetValue()
        te_content = self.te_content.GetValue()
        if te_name == '':
            dlg = wx.MessageDialog(self.recordframe, u'请输入记录标题', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        if te_content == '':
            dlg = wx.MessageDialog(self.recordframe, u'请输入记录内容', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        self.__cs.execute("insert into pwk_data values(null,'" + self.secure.endecrypt(te_name, self.key, True) + "','" + self.secure.endecrypt(te_content, self.key, True) + "','" + time.strftime('%Y-%m-%d %H:%M:%S') + "',1)")
        self.__conn.commit()
        self.recordframe.Close()
        self.pwlistload()

    def onpwlistselected(self, event):
        self.dataindex = event.GetIndex()
        self.did = self.pwlistboard.GetItem(self.dataindex, 0).GetText()
        self.__cs.execute('select * from pwk_data where did=' + self.did)
        data = self.__cs.fetchone()
        self.pwshowboard.SetValue(self.secure.endecrypt(data[2], self.key))
        self.frame.SetStatusText(self.secure.endecrypt(data[1], self.key))

    def onchangepwd(self, event):
        if self.changepwdframeshow == True:
            return False
        self.changepwdframeshow = True
        self.changepwdframe = Frame(title = u'修改安全密码')
        panel = wx.Panel(self.changepwdframe)
        sizer = wx.BoxSizer(wx.VERTICAL)
        lb_oripwd = wx.StaticText(panel, wx.ID_ANY, u'初始密码:')
        self.te_oripwd = wx.TextCtrl(panel, wx.ID_ANY, size = (215, 25), style = wx.TE_PASSWORD)
        self.te_oripwd.SetFont(self.font)
        lb_pwd = wx.StaticText(panel, wx.ID_ANY, u'密码:')
        self.te_pwd = wx.TextCtrl(panel, wx.ID_ANY, size = (215, 25), style = wx.TE_PASSWORD)
        self.te_pwd.SetFont(self.font)
        lb_cpwd = wx.StaticText(panel, wx.ID_ANY, u'确认密码:')
        self.te_cpwd = wx.TextCtrl(panel, wx.ID_ANY, size = (215, 25), style = wx.TE_PASSWORD)
        self.te_cpwd.SetFont(self.font)
        btn_submit = wx.Button(panel, wx.ID_ANY, u'确定')
        panel.Bind(wx.EVT_BUTTON, self.setpwdchange, btn_submit)
        self.changepwdframe.Bind(wx.EVT_CLOSE, self.onchangepwdframeclose, self.changepwdframe)
        sizer.Add(lb_oripwd, 0, wx.LEFT|wx.TOP|wx.RIGHT)
        sizer.Add(self.te_oripwd, 0, wx.TOP|wx.RIGHT|wx.EXPAND)
        sizer.Add(lb_pwd, 0, wx.LEFT|wx.RIGHT)
        sizer.Add(self.te_pwd, 0, wx.RIGHT|wx.EXPAND)
        sizer.Add(lb_cpwd, 0, wx.LEFT|wx.RIGHT)
        sizer.Add(self.te_cpwd, 1, wx.RIGHT|wx.EXPAND)
        sizer.Add(btn_submit, 0, wx.CENTER)
        panel.SetSizer(sizer)
        sizer.Fit(self.changepwdframe)
        self.changepwdframe.Show()

    def setpwdchange(self, event):
        te_oripwd = self.te_oripwd.GetValue()
        te_pwd = self.te_pwd.GetValue()
        te_cpwd = self.te_cpwd.GetValue()
        if te_oripwd == '':
            dlg = wx.MessageDialog(self.changepwdframe, u'请输入初始密码', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        if len(te_pwd) < 6:
            dlg = wx.MessageDialog(self.changepwdframe, u'新密码要大于等于6位哦', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        self.__cs.execute('select * from pwk_secure')
        data = self.__cs.fetchone()
        if te_oripwd != self.secure.endecrypt(data[1], "don't panic."):
            self.te_oripwd.SetValue('')
            self.te_pwd.SetValue('')
            self.te_cpwd.SetValue('')
            dlg = wx.MessageDialog(self.changepwdframe, u'初始密码错误，请重试', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        if te_pwd != te_cpwd:
            dlg = wx.MessageDialog(self.changepwdframe, u'新密码和确认密码不一致', u'提示', wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            return False
        self.__cs.execute("update pwk_secure set pw='" + self.secure.endecrypt(te_pwd, "don't panic.", True) + "' where uid=" + str(data[0]))
        self.__conn.commit()
        dlg = wx.MessageDialog(self.changepwdframe, u'修改密码成功', u'提示', wx.OK)
        dlg.ShowModal()
        dlg.Destroy()
        self.changesecurekey("don't" + te_pwd + ' panic.')
        self.changepwdframe.Close()
        self.changepwdframeshow = False

    def changesecurekey(self, newkey):
        self.__cs.execute('select * from pwk_data')
        data = self.__cs.fetchall()
        for i in data:
            name = self.secure.endecrypt(i[1], self.key)
            content = self.secure.endecrypt(i[2], self.key)
            self.__cs.execute("update pwk_data set name='" + self.secure.endecrypt(name, newkey, True) + "',content='" + self.secure.endecrypt(content, newkey, True) + "' where did=" + str(i[0]))
            self.__conn.commit()
        self.key = newkey
        self.pwlistload()

    def onchangepwdframeclose(self, event):
        self.changepwdframe.Destroy()
        self.changepwdframeshow = False

    def pwlistload(self):
        self.pwlistboard.DeleteAllItems()
        self.__cs.execute('select * from pwk_data')
        data = self.__cs.fetchone()
        while data:
            pos = self.pwlistboard.InsertStringItem(0, str(data[0]))
            self.pwlistboard.SetStringItem(pos, 1, self.secure.endecrypt(data[1], self.key))
            self.pwlistboard.SetStringItem(pos, 2, data[3])
            data = self.__cs.fetchone()
        self.pwshowboard.SetValue('')
        self.frame.SetStatusText('')

    def pwlistmenu(self, event):
        if not hasattr(self, 'popupedit'):
            self.popupedit = wx.NewId()
            self.popupdel = wx.NewId()
            self.Bind(wx.EVT_MENU, self.onpopupedit, id = self.popupedit)
            self.Bind(wx.EVT_MENU, self.onpopupdel, id = self.popupdel)
        menu = wx.Menu()
        itemedit = wx.MenuItem(menu, self.popupedit, u'编辑')
        itemdel = wx.MenuItem(menu, self.popupdel, u'删除')
        menu.AppendItem(itemedit)
        menu.AppendItem(itemdel)
        self.frame.PopupMenu(menu)
        menu.Destroy()

    def onpopupedit(self, event):
        if self.recordframeshow:
            return False
        self.recordframe = Frame(title = u'编辑记录')
        panel = wx.Panel(self.recordframe)
        sizer = wx.BoxSizer(wx.VERTICAL)
        lb_name = wx.StaticText(panel, wx.ID_ANY, u'名称:')
        self.te_name = wx.TextCtrl(panel, wx.ID_ANY, size = (400, -1))
        self.te_name.SetFont(self.font)
        self.updatedid = self.did
        self.__cs.execute('select * from pwk_data where did=' + self.updatedid)
        data = self.__cs.fetchone()
        self.te_name.SetValue(self.secure.endecrypt(data[1], self.key))
        lb_content = wx.StaticText(panel, wx.ID_ANY, u'内容:')
        self.te_content = wx.TextCtrl(panel, wx.ID_ANY, style = wx.TE_MULTILINE, size = (400, 300))
        self.te_content.SetFont(self.font)
        self.te_content.SetValue(self.secure.endecrypt(data[2], self.key))
        btn_submit = wx.Button(panel, wx.ID_ANY, u'确定')
        panel.Bind(wx.EVT_BUTTON, self.updaterecordsubmit, btn_submit)
        sizer.Add(lb_name, 0, wx.LEFT|wx.TOP|wx.RIGHT)
        sizer.Add(self.te_name, 0, wx.TOP|wx.RIGHT|wx.EXPAND)
        sizer.Add(lb_content, 0, wx.LEFT|wx.RIGHT)
        sizer.Add(self.te_content, 1, wx.RIGHT|wx.EXPAND)
        sizer.Add(btn_submit, 0, wx.CENTER)
        panel.SetSizer(sizer)
        sizer.Fit(self.recordframe)
        self.recordframe.Show()
        self.recordframeshow = True
        self.recordframe.Bind(wx.EVT_CLOSE, self.__recordframeclose, self.recordframe)

    def onpopupdel(self, event):
        self.__cs.execute('delete from pwk_data where did=' + self.did)
        self.__conn.commit()
        self.pwlistboard.DeleteItem(self.dataindex)
        self.pwshowboard.SetValue('')
        self.frame.SetStatusText('')

    def onhelpmenuabout(self, event):
        dlg = wx.MessageDialog(self.frame, u"A Simple Password Kit\r\n\r\n(c) Geeklevin", u'关于', wx.OK)
        dlg.ShowModal()
        dlg.Destroy()

    def __dbinit(self):
        self.__conn = sqlite3.connect('./data.db')
        self.__cs = self.__conn.cursor()
        return self.__tableinit()

    def __tableinit(self):
        try:
            self.__cs.execute('create table pwk_data (did integer primary key autoincrement,name text,content text,last_modified datetime,order_num integer)')
            return 1
        except sqlite3.OperationalError:
            return 2

    def __recordframeclose(self, event):
        self.recordframe.Unbind(wx.EVT_CLOSE, self.recordframe)
        self.recordframeshow = False
        self.recordframe.Close()

    def __exit(self, event):
        self.__conn.close()
        self.Exit()

app = App()
app.MainLoop()
