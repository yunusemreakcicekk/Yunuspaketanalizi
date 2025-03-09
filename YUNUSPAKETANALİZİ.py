import pyshark
import tkinter as tk
from tkinter import scrolledtext, filedialog
import threading

capturing = False

def start_packet_capture():
    global capturing
    capturing = True
    capture_output.delete(1.0, tk.END)
    capture = pyshark.LiveCapture(interface='eth0')
    capture_output.insert(tk.END, "🎧 Paketler dinleniyor...\n", "info")

    def capture_loop():
        try:
            for packet in capture.sniff_continuously():
                if not capturing:
                    break
                log_entry = ""
                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    log_entry += f"\n🌐 [DNS] Alan Adı Yakalandı!\n"
                    log_entry += f"🔹 Sorgu: {packet.dns.qry_name}\n"
                    log_entry += f"Yanıt: {getattr(packet.dns, 'a', 'Yok')}\n"
                    log_entry += "-" * 40 + "\n"
                    capture_output.insert(tk.END, log_entry, "dns")

                if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
                    log_entry += f"\n🔒 [TLS] Güvenli Bağlantı Yakalandı!\n"
                    log_entry += f"🔹 Site: {packet.tls.handshake_extensions_server_name}\n"
                    log_entry += "-" * 40 + "\n"
                    capture_output.insert(tk.END, log_entry, "tls")

                if hasattr(packet, 'tcp'):
                    log_entry += f"\n📡 [TCP] Veri Aktarımı Yakalandı!\n"
                    log_entry += f"🔹 Kaynak IP: {packet.ip.src} → Hedef IP: {packet.ip.dst}\n"
                    log_entry += f"🔹 Kaynak Port: {packet.tcp.srcport} | Hedef Port: {packet.tcp.dstport}\n"
                    if packet.tcp.srcport in ('80', '443') or packet.tcp.dstport in ('80', '443'):
                        log_entry += "🔒 HTTPS/TCP Trafiği\n"
                    log_entry += "-" * 40 + "\n"
                    capture_output.insert(tk.END, log_entry, "tcp")
        except KeyboardInterrupt:
            capture_output.insert(tk.END, "\n❌ Çıkış yapılıyor...\n", "error")

    threading.Thread(target=capture_loop, daemon=True).start()

def stop_packet_capture():
    global capturing
    capturing = False
    capture_output.insert(tk.END, "\n⏹ Paket dinleme durduruldu.\n", "error")

def exit_application():
    stop_packet_capture()
    root.quit()

def clear_output():
    capture_output.delete(1.0, tk.END)

def save_output():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(capture_output.get(1.0, tk.END))

root = tk.Tk()
root.title("🖥 Yunus Paket Analizi")
root.geometry("700x500")
root.configure(bg="#222222")

label = tk.Label(root, text="📡 Yunus Paket Analizi", font=("Arial", 16, "bold"), fg="white", bg="#222222")
label.pack(pady=10)

button_frame = tk.Frame(root, bg="#222222")
button_frame.pack(pady=5)
start_button = tk.Button(button_frame, text="🎧 Dinle", font=("Arial", 12), bg="#4CAF50", fg="white", 
                         command=start_packet_capture)
start_button.grid(row=0, column=0, padx=5)
stop_button = tk.Button(button_frame, text="⏹ Durdur", font=("Arial", 12), bg="#FF9800", fg="black", 
                        command=stop_packet_capture)
stop_button.grid(row=0, column=1, padx=5)
clear_button = tk.Button(button_frame, text="🧹 Temizle", font=("Arial", 12), bg="#FFC107", fg="black", 
                         command=clear_output)
clear_button.grid(row=0, column=2, padx=5)
save_button = tk.Button(button_frame, text="💾 Kaydet", font=("Arial", 12), bg="#03A9F4", fg="white", 
                        command=save_output)
save_button.grid(row=0, column=3, padx=5)
exit_button = tk.Button(button_frame, text="❌ Çıkış", font=("Arial", 12), bg="#FF5733", fg="white", 
                        command=exit_application)
exit_button.grid(row=0, column=4, padx=5)

capture_output = scrolledtext.ScrolledText(root, width=80, height=20, font=("Consolas", 10), bg="#333333", 
                                           fg="white", wrap=tk.WORD)
capture_output.pack(padx=10, pady=10)

capture_output.tag_config("info", foreground="lightblue")
capture_output.tag_config("dns", foreground="yellow")
capture_output.tag_config("tls", foreground="lightgreen")
capture_output.tag_config("tcp", foreground="cyan")
capture_output.tag_config("error", foreground="red")

root.mainloop()

