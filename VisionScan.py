import os
import platform
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import pytesseract

# Configurar la ruta de Tesseract en Windows
if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = r"C:\\Program Files\\Tesseract-OCR\\tesseract.exe"

# Crear ventana principal
root = tk.Tk()
root.title("VisionScan.v1.3.0")
root.geometry("600x500")
root.configure(bg="#ffffff")

# Estilos personalizados
style = ttk.Style()
style.configure("TFrame", background="#ffffff")
style.configure("TButton", font=("Arial", 10, "bold"), padding=6)
style.configure("TLabel", font=("Arial", 12, "bold"), background="#ffffff")

# Función para seleccionar carpeta
def seleccionar_carpeta():
    carpeta = filedialog.askdirectory()
    if carpeta:
        entry_folder.delete(0, tk.END)
        entry_folder.insert(0, carpeta)

# Función para buscar texto en imágenes
def buscar_texto():
    carpeta = entry_folder.get()
    frase = entry_phrase.get()
    idioma = language_options[language_var.get()]
    if not carpeta or not frase:
        messagebox.showwarning("Advertencia", "Debes seleccionar una carpeta y escribir una frase para buscar.")
        return
    
    listbox.delete(0, tk.END)
    extensiones = ('.png', '.jpg', '.jpeg', '.bmp', '.tif', '.tiff')
    archivos = [f for f in os.listdir(carpeta) if f.lower().endswith(extensiones)]
    total = len(archivos)
    
    if total == 0:
        messagebox.showinfo("Sin imágenes", "No se encontraron imágenes en la carpeta seleccionada.")
        return
    
    progress['value'] = 0
    progress['maximum'] = total
    
    for idx, nombre in enumerate(archivos, start=1):
        ruta = os.path.join(carpeta, nombre)
        try:
            imagen = Image.open(ruta)
            texto = pytesseract.image_to_string(imagen, lang=idioma)
        except Exception as e:
            texto = ""
        
        if frase.lower() in texto.lower():
            listbox.insert(tk.END, nombre)
        
        progress['value'] = idx
        root.update_idletasks()
    
    if listbox.size() == 0:
        messagebox.showinfo("No encontrado", "No se encontraron imágenes con la frase buscada.")

# Función para guardar resultados
def guardar_resultados():
    resultados = listbox.get(0, tk.END)
    if not resultados:
        messagebox.showwarning("Advertencia", "No hay resultados para guardar.")
        return
    archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if archivo:
        with open(archivo, "w") as f:
            for resultado in resultados:
                f.write(resultado + "\n")
        messagebox.showinfo("Guardado", "Resultados guardados correctamente.")

# Función para abrir imagen
def abrir_imagen():
    seleccion = listbox.curselection()
    if not seleccion:
        messagebox.showwarning("Advertencia", "Selecciona una imagen de la lista para abrir.")
        return
    nombre_archivo = listbox.get(seleccion[0])
    ruta_archivo = os.path.join(entry_folder.get(), nombre_archivo)
    os.startfile(ruta_archivo)

# Marco contenedor
frame = ttk.Frame(root, padding=15, style="TFrame")
frame.pack(fill=tk.BOTH, expand=True)

# Título decorativo
title_label = ttk.Label(frame, text="🔍 VisionScan", font=("Arial", 16, "bold"))
title_label.grid(row=0, column=0, columnspan=3, pady=5)

# Campo para carpeta
ttk.Label(frame, text="📂 Carpeta:").grid(row=1, column=0, sticky="w", pady=2)
entry_folder = ttk.Entry(frame, width=50)
entry_folder.grid(row=1, column=1, padx=5, pady=2)
ttk.Button(frame, text="Seleccionar", command=seleccionar_carpeta).grid(row=1, column=2, padx=5, pady=2)

# Campo para frase a buscar
ttk.Label(frame, text="📝 Frase a buscar:").grid(row=2, column=0, sticky="w", pady=2)
entry_phrase = ttk.Entry(frame, width=50)
entry_phrase.grid(row=2, column=1, columnspan=2, padx=5, sticky="we", pady=2)

# Selección de idioma OCR
ttk.Label(frame, text="🌍 Idioma OCR:").grid(row=3, column=0, sticky="w", pady=2)
language_options = {"Español": "spa", "Inglés": "eng", "Francés": "fra", "Alemán": "deu"}
language_var = tk.StringVar(value="spa")
language_menu = ttk.Combobox(frame, textvariable=language_var, values=list(language_options.keys()), state="readonly", width=10)
language_menu.grid(row=3, column=1, padx=5, pady=2, sticky="w")

# Barra de progreso
progress = ttk.Progressbar(frame, length=400, mode='determinate')
progress.grid(row=4, column=0, columnspan=3, pady=5)

# Botón de búsqueda
btn_search = ttk.Button(frame, text="🔎 Buscar", command=buscar_texto)
btn_search.grid(row=5, column=0, columnspan=3, pady=5)

# Listbox para resultados con scrollbar
listbox_frame = ttk.Frame(frame)
listbox_frame.grid(row=6, column=0, columnspan=3, pady=5, sticky="nsew")
listbox = tk.Listbox(listbox_frame, width=80, height=6, font=("Arial", 10))
listbox.pack(side="left", fill="both", expand=True)
scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=listbox.yview)
scrollbar.pack(side="right", fill="y")
listbox.config(yscrollcommand=scrollbar.set)

# Botones extra
button_frame = ttk.Frame(frame)
button_frame.grid(row=7, column=0, columnspan=3, pady=5)
ttk.Button(button_frame, text="🖼 Abrir Imagen", command=abrir_imagen).grid(row=0, column=0, padx=5)
ttk.Button(button_frame, text="💾 Guardar Resultados", command=guardar_resultados).grid(row=0, column=1, padx=5)

# Línea de crédito
credit_frame = ttk.Frame(root, padding=5, style="TFrame")
credit_frame.pack(fill=tk.BOTH, expand=True)
ttk.Label(credit_frame, text="Nizert", font=("Arial", 10, "bold"), foreground="gray").pack()
ttk.Label(credit_frame, text="Creador: Diego Alvarado", font=("Arial", 9), foreground="gray").pack()

root.mainloop()
