import ttk
import urllib2
from urllib2 import urlopen
from lxml import etree
from Tkinter import *
from ttk import *
import tkMessageBox

root = Tk()
root.wm_title("SSDEEP Tool")
root.resizable(False, False)

SSDeep_list = []


def Get_SSDEEP_List():
    TBox2.delete(1.0, END)
    TBox3.delete(1.0, END)
    Tbox_Data = TBox1.get("1.0", END).splitlines()
    for line in Tbox_Data:
        try:
            VT_Data(line)
        except Exception as e:
            print(e)
    tkMessageBox.showinfo("Done", "Finished!")


def Get_SSDEEP(tree):
    vt_SSDEEP = tree.xpath('//*[@id="file-details"]/div[1]/div[4]/div[2]/text()')[0]
    SSDeep_list.append(vt_SSDEEP)
    print("working...")
    TBox2.insert(END,vt_SSDEEP +"\n")

def Get_VT(hash):
    try:
        response = urlopen("https://virustotal.com/en/file/" + hash + "/analysis/")
        return response
    except urllib2.HTTPError as err:
        if err.code == 403:
            print(err)
            print("Please solve the captcha before you continue")
            input("Press enter after solving captcha")

def VT_Detectiones(tree,hash):
    TBox3.insert(END, "\n---------------------------------------------------------------\n" + hash + "\n---------------------------------------------------------------\n")
    for tbl in tree.xpath("//table[@id='antivirus-results']"):
        elements = tbl.xpath('.//tr/td//text()')
        temp = []
        vt_results = []
        for a in elements:
            temp.append(a.strip())
        for s in temp:
            if (s == ''):
                break
            vt_results.append(s)
        vt_results = vt_results[:-1]
        for var in vt_results:
            if(var=="ESET-NOD32"):
                TBox3.insert(END, "ESET-NOD32 - " + vt_results[vt_results.index(var) + 1] + "\n")
            if (var == "Kaspersky"):
                TBox3.insert(END, "Kaspersky - " + vt_results[vt_results.index(var) + 1] + "\n")
            if (var == "Malwarebytes"):
                TBox3.insert(END, "Malwarebytes - " + vt_results[vt_results.index(var) + 1] + "\n")
            if (var == "Microsoft"):
                TBox3.insert(END, "Microsoft - " + vt_results[vt_results.index(var) + 1] + "\n\n\n")

def VT_Data(hash):

    b = Get_VT(hash)
    var1 = b.geturl()
    var2 = 'https://www.virustotal.com/en/file/not/found/'
    if (var1 == var2):
        SSDeep_list.append("Hash not in VT")
        TBox2.insert(END,"Hash not in VT\n")
    else:
        htmlparser = etree.HTMLParser()
        tree = etree.parse(b, htmlparser)
        Get_SSDEEP(tree)
        VT_Detectiones(tree,hash)
        

def Copy_Text():
    root.clipboard_clear()
    Str = "\n".join(SSDeep_list)
    root.clipboard_append(Str)


# GUI
notebook = ttk.Notebook(root)
# Reanalyze Files tab
Sha256_to_SSDeeP_frame = Frame(root)
notebook.add(Sha256_to_SSDeeP_frame, text='Get SSDeep')

notebook.grid()
# Files Reanalyze GUI
Lbl = Label(Sha256_to_SSDeeP_frame, text="Hash:")

TBox1 = Text(Sha256_to_SSDeeP_frame)
TBox1.config(height=10, width=90)
TBox1.grid(row=0, column=1)

TBox2 = Text(Sha256_to_SSDeeP_frame)
TBox2.config(height=10, width=90)
TBox2.grid(row=2, column=1)

TBox3 = Text(Sha256_to_SSDeeP_frame)
TBox3.config(height=10, width=90)
TBox3.grid(row=4, column=1)


GetSSDEEP_Btn = Button(Sha256_to_SSDeeP_frame, text="Get SSDEEP", command=Get_SSDEEP_List)
GetSSDEEP_Btn.grid(row=1, column=1)
scrollb = Scrollbar(Sha256_to_SSDeeP_frame, command=TBox1.yview)
scrollb.grid(row=0, column=2, sticky='nsew')
TBox1['yscrollcommand'] = scrollb.set

CopySSDEEP_Btn = Button(Sha256_to_SSDeeP_frame, text="Copy SSDEEP", command=Copy_Text)
CopySSDEEP_Btn.grid(row=3, column=1)

scrollb1 = Scrollbar(Sha256_to_SSDeeP_frame, command=TBox2.yview)
scrollb1.grid(row=2, column=2, sticky='nsew')
TBox2['yscrollcommand'] = scrollb1.set

scrollb2 = Scrollbar(Sha256_to_SSDeeP_frame, command=TBox3.yview)
scrollb2.grid(row=4, column=2, sticky='nsew')
TBox3['yscrollcommand'] = scrollb2.set

Lbl_name = Label(root, text="Developed by Nofar2. with the support of Avi, Shlomi and Max")
Lbl_name.grid(sticky=S)
Lbl_name.config(font=("", 7))

root.mainloop()
