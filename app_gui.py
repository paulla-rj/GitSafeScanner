import customtkinter as ctk
from tkinter import filedialog, messagebox
import subprocess
import os
import threading
import webbrowser

# Configuração geral
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Função para escolher repositório
def escolher_pasta():
    pasta = filedialog.askdirectory(title="Selecione o repositório clonado")
    if pasta:
        entrada_pasta.set(pasta)

# Função para rodar o scanner em thread separada
def rodar_scanner_thread():
    threading.Thread(target=rodar_scanner, daemon=True).start()

# Função principal do scanner
def rodar_scanner():
    pasta = entrada_pasta.get()
    if not pasta:
        messagebox.showerror("Erro", "Escolha uma pasta primeiro!")
        return

    saida_dir = os.path.join(os.path.expanduser("~"), "relatorios")
    os.makedirs(saida_dir, exist_ok=True)
    saida = os.path.join(saida_dir, "relatorio.txt")

    comando = ["python", "scanner/static_repo_scanner.py", pasta, "--out", saida]

    barra_progresso.set(0)
    label_status.configure(text="Rodando scanner...")
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True)
        barra_progresso.set(100)
        label_status.configure(text="Scanner finalizado!")
        texto_resultado.configure(state="normal")
        texto_resultado.delete("1.0", ctk.END)
        texto_resultado.insert(ctk.END, resultado.stdout or "Scanner executado com sucesso!")
        texto_resultado.configure(state="disabled")
        btn_abrir_relatorio.configure(state="normal")
    except Exception as e:
        messagebox.showerror("Erro", str(e))
        label_status.configure(text="Erro ao rodar scanner")
        barra_progresso.set(0)

# Função para abrir relatório
def abrir_relatorio():
    saida_dir = os.path.join(os.path.expanduser("~"), "relatorios")
    saida = os.path.join(saida_dir, "relatorio.txt")
    if os.path.exists(saida):
        webbrowser.open(saida)
    else:
        messagebox.showerror("Erro", "Relatório não encontrado.")

# Janela principal
janela = ctk.CTk()
janela.title("GitSafeScanner")
janela.geometry("700x450")

# Label e entrada
ctk.CTkLabel(janela, text="Escolha o repositório clonado do GitHub:", font=ctk.CTkFont(size=16)).pack(pady=10)
entrada_pasta = ctk.StringVar()
ctk.CTkEntry(janela, textvariable=entrada_pasta, width=500).pack(pady=5)
ctk.CTkButton(janela, text="Procurar", width=120, command=escolher_pasta).pack(pady=5)

# Botão rodar scanner
ctk.CTkButton(janela, text="Rodar Scanner", width=200, command=rodar_scanner_thread).pack(pady=10)

# Barra de progresso
barra_progresso = ctk.CTkProgressBar(janela, width=500)
barra_progresso.set(0)
barra_progresso.pack(pady=10)

# Label status
label_status = ctk.CTkLabel(janela, text="Aguardando ação...")
label_status.pack(pady=5)

# Área de resultado
texto_resultado = ctk.CTkTextbox(janela, width=600, height=150)
texto_resultado.pack(pady=10)
texto_resultado.configure(state="disabled")

# Botão abrir relatório
btn_abrir_relatorio = ctk.CTkButton(janela, text="Abrir relatório", width=180, command=abrir_relatorio, state="disabled")
btn_abrir_relatorio.pack(pady=5)

janela.mainloop()

