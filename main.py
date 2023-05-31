import os
import codecs
import win32security
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

root = tk.Tk()
root.title('Атрибуты безопасности')
root.geometry('1200x650')
root.configure(bg="lavender")

root.grid_rowconfigure(index=0, weight=1)
root.grid_rowconfigure(index=1, weight=1)
root.grid_rowconfigure(index=2, weight=1)
root.grid_rowconfigure(index=3, weight=1)
root.grid_columnconfigure(index=0, weight=1)
root.grid_columnconfigure(index=1, weight=1)
root.grid_columnconfigure(index=2, weight=1)
root.grid_columnconfigure(index=3, weight=1)

text_editor = tk.Text()
text_editor.grid(column=1, columnspan=2, row=1)

dacls = []
flagbtn = []

def create_file_2(dir, file, window):
    if dir != '' and file != '':
        Path(dir + '/' + file).touch(exist_ok=True)
    window.destroy()


def create_file():
    directorypath = tk.filedialog.askdirectory()
    window = tk.Tk()
    window.title('Создание файла')
    window.geometry('250x100')
    label = tk.Label(window, text='Введите название файла')
    label.pack()
    entry = tk.Entry(window)
    entry.pack()
    ok_button = tk.Button(window, text='Создать', command=lambda: create_file_2(directorypath, entry.get(), window))
    ok_button.pack()


def open_file():
    filepath = tk.filedialog.askopenfilename()
    if filepath != '':
        label.config(text='Открытый файл: ' + filepath)
        with codecs.open(filepath, 'r', 'utf-8') as file:
            try:
                text = file.read()
            except:
                text = 'Ошибка чтения'
            text_editor.delete('1.0', tk.END)
            text_editor.insert('1.0', text)


def save_file():
    filepath = tk.filedialog.askopenfilename()
    if filepath != '':
        text = text_editor.get('1.0', tk.END)
        with codecs.open(filepath, 'w', 'utf-8') as file:
            file.write(text)


def remove_file():
    filepath = tk.filedialog.askopenfilename()
    if filepath != '':
        os.remove(filepath)


def set_dacl():
    filepath = label.cget('text')[15:]
    username = user_entry.get()
    if filepath != '' and username != '':
        flags = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
        sd = win32security.GetNamedSecurityInfo(
            filepath,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        ace_count = dacl.GetAceCount()
        counter = ace_count
        for i in range(0, ace_count):
            dacl.DeleteAce(0)
        read_data = 1  #цифровые значения атрибутов
        read_attributes = 128
        read_extended_attributes = 8
        write_data = 2
        append_data = 4
        add_subdirectory = 4
        write_attributes = 256
        write_extended_attributes = 16
        delete = 65536
        change_permsission = 262144
        read_permission = 131072
        take_ownership = 524288
        execute = 32
        read_only = 1179785
        write_only = 1048854
        full_access = 2032127
        modify_only = 1245631
        read_and_execute = 1179817
        clear = 0
        user, domain, type = win32security.LookupAccountName('', username)
        if dacls[0].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                execute,
                user
            )
        if dacls[1].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                read_data,
                user
            )
        if dacls[2].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                read_attributes,
                user
            )
        if dacls[3].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                read_extended_attributes,
                user
            )
        if dacls[4].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                write_data,
                user
            )
        if dacls[5].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                append_data,
                user
            )
        if dacls[6].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                write_attributes,
                user
            )
        if dacls[7].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                write_extended_attributes,
                user
            )
        if dacls[8].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                delete,
                user
            )
        if dacls[9].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                read_permission,
                user
            )
        if dacls[10].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                change_permsission,
                user
            )
        if dacls[11].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                take_ownership,
                user
            )
        if dacls[12].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                add_subdirectory,
                user
            )
        if dacls[13].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                read_only,
                user
            )
        if dacls[14].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                write_only,
                user
            )
        if dacls[15].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                read_and_execute,
                user
            )
        if dacls[16].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                modify_only,
                user
            )
        if dacls[17].get() == 1:
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                full_access,
                user
            )
        win32security.SetNamedSecurityInfo(
            filepath,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None
        )


open_button = tk.Button(text='Открыть файл', command=open_file)
open_button.grid(column=0, row=0, padx=10)

save_button = tk.Button(text='Создать файл', command=create_file)
save_button.grid(column=1, row=0, padx=10)

save_button = tk.Button(text='Сохранить файл', command=save_file)
save_button.grid(column=2, row=0, padx=10)

save_button = tk.Button(text='Удалить файл', command=remove_file)
save_button.grid(column=3, row=0, padx=10)

label = tk.Label(text='Содержимое файла: ')
label.grid(column=0, columnspan=1, row=1, padx=10)

user_label = tk.Label(text='Пользователь')
user_label.grid(column=0, row=2, padx=10, pady=10)
user_entry = tk.Entry()
user_entry.grid(column=1, row=2, padx=10, pady=10)

dacl_button = tk.Button(text='Применить атрибуты', command=set_dacl)
dacl_button.grid(column=2, columnspan=2, row=2, padx=10)

dacls_label = ['Вполнение', 'Чтение содержимого', 'Чтение атрибутов', 'Чтение расширенных атрибутов',
               'Запись данных', 'Добавление данных', 'Запись атрибутов', 'Запись расширенных атрибутов', 'Удаление',
               'Чтение разрешений', 'Изменение разрешений', 'Владение', 'Добавление Подпапки', 'Чтение', 'Запись',
               'Чтение и Выполнение', 'Изменение', 'Полный доступ']

for i in range(18):
    dacls.append(tk.IntVar())
    flagbtn.append(tk.Checkbutton(text=dacls_label[i], variable=dacls[i]))
    flagbtn[i].grid(column=i % 3, row=i // 3 + 5, padx=10)

root.mainloop()