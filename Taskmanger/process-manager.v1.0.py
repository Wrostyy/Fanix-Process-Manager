import tkinter as tk
import psutil
import subprocess
import webbrowser  # Web sayfalarını açmak için
from tkinter import filedialog
from tkinter import ttk
import sys

def on_close():
    sys.exit()  # Uygulamayı kapat

root = tk.Tk()
root.title("Terms of Service")
root.geometry("600x190")
root.iconbitmap(default='fanix.ico')
root.resizable(width=False, height=False)

# Kullanıcının kabul etmesi gereken metni burada tanımlayın
terms_text = """
Fanix Bot Service ve Fanix Process Manager uygulamasını ve alanlarını (Bot hizmetleri, Uygulama hizmetlerini)
kullandığınız için Hizmet şartlarına uymayı kabul ediyorsunuz.
Gizlilik; sizler üzerinden herhangibir bilgi transferi, bilgi depolama söz konusu değildir.
Tarafınızdan program üzerinden yanlış hamleler gütmeniz sonucu oluşacak tüm olaylar 
    sorumluluğumuz dışındadır!
"""

root.protocol("WM_DELETE_WINDOW", on_close)  # Sağ üst köşedeki çarpı simgesine tıklanınca on_close fonksiyonunu çağır

terms_label = tk.Label(root, text=terms_text, padx=10, pady=10)
terms_label.pack()

accept_button = tk.Button(root, text="Kabul Et", command=lambda: run_task_manager(root))
accept_button.pack()

cancel_button = tk.Button(root, text="İptal", command=on_close)
cancel_button.pack()

def run_task_manager(root):
    root.destroy()  # Onay penceresini kapat
    subprocess.Popen(["python", "taskmanager_original.py"])  # Task Manager'ı başlat

root.mainloop()



# Göstermek istemediğiniz exeleri listeleyin
ignore_list = ["chrome.exe","nvcontainer.exe","Registry","fontdrvhost.exe","rundll32.exe","sihost.exe","gamingservicesnet.exe","rvcontrolsvc.exe","MemCompression","microsoft.photos.exe","gameinputsvc.exe","taskhostw.exe","systemsettings.exe","smartscreen.exe","TextInputHost.exe","syzs_dl_svr.exe","powershell.exe","CompPkgSrv.exe","AppMarket.exe","dwm.exe","winlogon.exe","dashost.exe","spoolsv.exe","Securityhealthservice.exe","Securityhealthsystray.exe","SearchApp.exe","explorer.exe" ,"audiodg.exe","gamingservices.exe","System","smss.exe", "Lsass.exe", "RuntimeBroker.exe", "SearchProtocolHost.exe", "dllhost.exe","services.exe","wininit.exe","csrss.exe","ctfmon.exe","conhost.exe","cef_frame_render.exe","System Idle Process","sgrmbroker.exe","video.ui.exe","nvsphelper64.exe","SearchFilterHost.exe","mstsc.exe"]

# Bu değişken, filtreleme için kullanılacaktır
current_filter = None



def list_processes():
    process_list.delete(0, tk.END)
    process_info_dict = {}

    for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
        try:
            process_info = proc.info
            process_name = process_info['name']
            cpu_percent = process_info['cpu_percent']

            if process_name.lower() != "svchost.exe" and process_name.lower() not in (exe.lower() for exe in ignore_list):
                if process_name not in process_info_dict:
                    process_info_dict[process_name] = (process_info['pid'], cpu_percent, 1)
                else:
                    pid, old_cpu_percent, count = process_info_dict[process_name]
                    process_info_dict[process_name] = (pid, old_cpu_percent + cpu_percent, count + 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError):
            pass

    for process_name, (pid, cpu_percent, count) in sorted(process_info_dict.items(), key=lambda x: x[1][1], reverse=True):
        average_cpu_percent = cpu_percent / count
        if count > 1:
            process_list.insert(tk.END, f"PID: {pid}, İşlem Adı: {process_name} - CPU Kullanımı: {average_cpu_percent:.2f}% ({count})")
        else:
            process_list.insert(tk.END, f"PID: {pid}, İşlem Adı: {process_name} - CPU Kullanımı: {average_cpu_percent:.2f}%")



def open_file_location():
    selected_item = process_list.curselection()  # Seçilen öğeyi al
    if selected_item:
        index = selected_item[0]  # İlk seçilen öğeyi al
        process_info = process_list.get(index)  # Seçilen öğenin metnini al
        pid = int(process_info.split("PID: ")[1].split(",")[0])  # PID'yi çıkar
        try:
            process = psutil.Process(pid)
            file_path = process.exe()
            if file_path:
                subprocess.Popen(['explorer', '/select,', file_path])  # Dosya konumunu aç
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def update_process_list():
    list_processes()  # İşlem listesini güncelle
    root.after(10000, update_process_list)  # 10 saniye sonra tekrar güncelle

def on_delete_click():
    selected_item = process_list.curselection()  # Seçilen öğeyi al
    if selected_item:
        index = selected_item[0]  # İlk seçilen öğeyi al
        process_info = process_list.get(index)  # Seçilen öğenin metnini al
        pid = int(process_info.split("PID: ")[1].split(",")[0])  # PID'yi çıkar
        try:
            process = psutil.Process(pid)
            process.terminate()  # Seçilen işlemi sonlandır
            list_processes()  # İşlemi sonlandırdıktan sonra işlem listesini güncelle
        except psutil.NoSuchProcess:
            pass



def filter_processes(event):
    global current_filter
    key = event.char.lower()  # Basılan tuşun küçük harfi
    if key == current_filter:
        return
    current_filter = key
    process_list.delete(0, tk.END)
    process_info_list = {}

    for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
        try:
            process_info = proc.info
            process_name = process_info['name'].lower()  # İşlem adını küçük harfe çevir

            if process_name.lower() != "svchost.exe" and process_name.lower() not in (exe.lower() for exe in ignore_list):
                if process_name.startswith(key):
                    if process_name not in process_info_list:
                        process_info_list[process_name] = (process_info['pid'], process_info['cpu_percent'], 1)
                    else:
                        pid, old_cpu_percent, count = process_info_list[process_name]
                        process_info_list[process_name] = (pid, old_cpu_percent + process_info['cpu_percent'], count + 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    for process_name, (pid, cpu_percent, count) in sorted(process_info_list.items(), key=lambda x: x[1][1], reverse=True):
        average_cpu_percent = cpu_percent / count
        if count > 1:
            process_list.insert(tk.END, f"PID: {pid}, İşlem Adı: {process_name} - CPU Kullanımı: {average_cpu_percent:.2f}% ({count})")
        else:
            process_list.insert(tk.END, f"PID: {pid}, İşlem Adı: {process_name} - CPU Kullanımı: {average_cpu_percent:.2f}")

def open_discord():
    webbrowser.open("https://discord.gg/fanix")

def search_processes():
    search_term = search_entry.get()  # Arama terimini al
    process_list.delete(0, tk.END)  # Mevcut liste öğelerini temizle
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            process_info = proc.info
            process_name = process_info['name']
            
            # Windows'un kendi işlemlerini filtrele
            if not process_name.lower().startswith("system") and not process_name.lower() == "idle":
                if search_term.lower() in process_name.lower():  # Arama terimini içeriyorsa
                    process_list.insert(tk.END, f"PID: {process_info['pid']} İşlem Adı: {process_name}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


root = tk.Tk()
root.title("Fanix Process Manager")
root.iconbitmap(default='fanix.ico')

# Tema ayarları
style = ttk.Style()
style.configure("TButton", foreground="white", background="#0221bf")
style.configure("TLabel", foreground="black", background="white")
style.configure("TEntry", foreground="black", background="white")
style.configure("TListbox", foreground="black", background="white")

# Düğme 1: Çalışan İşlemleri Listele
button1 = ttk.Button(root, text="Çalışan İşlemleri Listele", command=list_processes)
button1.pack()

# Arama kutusu ve düğmesi
search_label = ttk.Label(root, text="Arama:")
search_label.pack()

search_entry = ttk.Entry(root)
search_entry.pack()

# Liste kutusu (listbox) oluştur
process_list = tk.Listbox(root, height=30, width=150, bg="white", fg="black", selectbackground="#0078d4", selectforeground="white")  # Burada genişliği ayarlayabilirsiniz
process_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Dikey kaydırma çubuğunu oluşturun
scrollbar = ttk.Scrollbar(root, orient="vertical", command=process_list.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Liste kutusunu dikey kaydırma çubuğu ile bağlayın
process_list.configure(yscrollcommand=scrollbar.set)

# Discord logosunu ekleyin ve tıklandığında bağlantıları açın
discord_logo_text = "Discord Server"
discord_logo_link = "https://discord.gg/fanix"

# Creator metnini ekleyin ve tıklandığında bağlantıyı açın
creator_text = "Creator"
creator_link = "https://github.com/Wrostyy"

creator_label = tk.Label(root, text=creator_text, cursor="hand2", fg="blue", underline=True)
creator_label.pack(anchor="se")  # Sağ alt köşeye yerleştirin

creator_label = tk.Label(root, text=discord_logo_text, cursor="hand2", fg="blue", underline=True)
creator_label.pack(anchor="se")  # Sağ alt köşeye yerleştirin

def open_server(event):
    webbrowser.open(discord_logo_link)

# Creator metnine tıklama işlevi ekleyin
def open_creator(event):
    webbrowser.open(creator_link)

creator_label.bind("<Button-1>", open_creator)
creator_label.bind("<Button-1>", open_server)

button_frame = tk.Frame(root)
button_frame.pack()

button2 = ttk.Button(button_frame, text="Sonlandır", command=on_delete_click)
button2.pack(side=tk.LEFT, padx=10)

open_folder_button = ttk.Button(button_frame, text="Dosya Konumunu Aç", command=open_file_location)
open_folder_button.pack(side=tk.LEFT, padx=10)

# Tuş olaylarını dinlemek için ana pencereye bağlanın
root.bind('<Key>', filter_processes)

update_process_list()



# Pencereyi göster
root.mainloop()

