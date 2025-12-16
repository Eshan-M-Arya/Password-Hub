import tkinter as tk
from tkinter import messagebox
import string


txt_colour = 'white'
bg_colour = '#242424'

# Initializing the main window
root_main = tk.Tk()
root_main.title("")
root_main.geometry("500x300")
root_main.config(bg=bg_colour)

# Centralizing the GUI elements in the main window
frame_main = tk.Frame()
frame_main.configure(bg=bg_colour)
frame_main.pack()


def confirm_exit():
    """Confirming user exit"""

    global root_main
    if messagebox.askyesno("Quit", "Are you sure you want to quit?"):
        root_main.destroy()


def password_strength_checker():
    def submit():
        """ Function to handle the tasks that happen after the submit button is clicked """

        password = pass_entry.get()

        if not password:
            messagebox.showwarning("Warning", "No password entered.")
        else:
            # Defining the res_label on the outer level
            nonlocal res_label

            checkbox_1.deselect()
            checkbox_2.deselect()
            checkbox_3.deselect()
            checkbox_4.deselect()
            checkbox_5.deselect()

            if len(password) >= 12:
                checkbox_5.select()

            for char in password:
                if char in string.ascii_uppercase: checkbox_1.select()
                if char in string.ascii_lowercase: checkbox_2.select()
                if char in string.digits: checkbox_3.select()
                if char in string.punctuation: checkbox_4.select()

            # Storing the number of checkboxes selected
            pass_score = checkbox_value_1.get() + checkbox_value_2.get() + checkbox_value_3.get() + checkbox_value_4.get() + checkbox_value_5.get()
            res_label.pack_forget()

            # Calculating the strength score of the password
            match pass_score:
                case 1:
                    res_label = tk.Label(frame, text="❌❌ Your password is very weak.",
                                         font=("Arial Rounded MT Bold", 14),
                                         fg='#8B0000', bg=bg_colour)
                case 2:
                    res_label = tk.Label(frame, text="❌ Your password is weak.", font=("Arial Rounded MT Bold", 14),
                                         fg='red', bg=bg_colour)
                case 3:
                    res_label = tk.Label(frame, text="❓ Your password needs more effort.",
                                         font=("Arial Rounded MT Bold", 14), fg='#32CD32', bg=bg_colour)
                case 4:
                    res_label = tk.Label(frame, text="✔️ Your password is strong.",
                                         font=("Arial Rounded MT Bold", 14),
                                         fg='orange', bg=bg_colour)
                case 5:
                    res_label = tk.Label(frame, text="✔️✔️ Your password is very strong.",
                                         font=("Arial Rounded MT Bold", 14), fg='yellow', bg=bg_colour)

            res_label.pack(pady=50)

    def event_handler(event):
        """Handles the Enter keystroke"""

        if (event.state == 0 or event.state == 2) and event.keysym == "Return":
            submit()

    def show_password():
        if checkbox_show_value.get() == 1:
            pass_entry.config(show="")
        else:
            pass_entry.config(show="*")

    # Initializing the Password Strength Checker window
    root = tk.Toplevel()
    root.title("Password Strength Checker")
    root.geometry("600x500")
    root.config(bg=bg_colour)

    # Centralizing the Password Strength Checker GUI elements
    frame = tk.Frame(root)
    frame.configure(bg=bg_colour)
    frame.pack()

    label = tk.Label(frame, text="🌟 Enter your password below: ", font=("Cascadia Code", 14), fg=txt_colour,
                     bg=bg_colour)
    label.pack(pady=2, anchor=tk.W)

    pass_entry = tk.Entry(frame, width=40, font=("Comic Sans MS", 15))
    pass_entry.bind("<KeyPress>", event_handler)
    pass_entry.pack(pady=13)
    pass_entry.config(show="*")

    # Checkbox to show/hide the password
    checkbox_show_value = tk.IntVar()
    checkbox_show = tk.Checkbutton(frame, text="Show Password", variable=checkbox_show_value,
                                   font=("Cascadia Code Semilight", 8), command=show_password, bg=bg_colour,
                                   fg='#00FF00', activebackground=bg_colour, activeforeground=txt_colour,
                                   selectcolor=bg_colour)
    checkbox_show.pack()

    submit_button = tk.Button(frame, text="Submit", font=("Arial", 15), command=submit, padx=5, pady=3, fg=bg_colour,
                              bg='#33B828',relief="raised",bd="10")
    submit_button.pack(pady=25)

    # These checkboxes get selected only if the password meets certain conditions
    checkbox_value_1 = tk.IntVar()
    checkbox_value_2 = tk.IntVar()
    checkbox_value_3 = tk.IntVar()
    checkbox_value_4 = tk.IntVar()
    checkbox_value_5 = tk.IntVar()
    checkbox_1 = tk.Checkbutton(frame, text="Contains at least 1 uppercase character", variable=checkbox_value_1,
                                state=tk.DISABLED, font=("Cascadia Code Semilight", 10), fg=txt_colour, bg=bg_colour)
    checkbox_1.pack(anchor=tk.W)
    checkbox_2 = tk.Checkbutton(frame, text="Contains at least 1 lowercase character", variable=checkbox_value_2,
                                state=tk.DISABLED, font=("Cascadia Code Semilight", 10), fg=txt_colour, bg=bg_colour)
    checkbox_2.pack(anchor=tk.W)
    checkbox_3 = tk.Checkbutton(frame, text="Contains at least 1 number", variable=checkbox_value_3,
                                state=tk.DISABLED, font=("Cascadia Code Semilight", 10), fg=txt_colour, bg=bg_colour)
    checkbox_3.pack(anchor=tk.W)
    checkbox_4 = tk.Checkbutton(frame, text="Contains at least 1 symbol", variable=checkbox_value_4,
                                state=tk.DISABLED, font=("Cascadia Code Semilight", 10), fg=txt_colour, bg=bg_colour)
    checkbox_4.pack(anchor=tk.W)
    checkbox_5 = tk.Checkbutton(frame, text="Is at least 12 characters long", variable=checkbox_value_5,
                                state=tk.DISABLED, font=("Cascadia Code Semilight", 10), fg=txt_colour, bg=bg_colour)
    checkbox_5.pack(anchor=tk.W)

    # Outputting the strength score of the password
    res_label = tk.Label(frame, text="", bg=bg_colour)
    res_label.pack()

    root.mainloop()


def password_encrypter_decrypter():
    def encrypt():
        encrypter = str.maketrans(chars, key)
        password = pass_entry.get()

        if not password:
            messagebox.showwarning("Warning", "No password entered.")

        pass_entry.delete(0, tk.END)
        pass_entry.insert(0, password.translate(encrypter))

    def decrypt():
        decrypter = str.maketrans(key, chars)
        password = pass_entry.get()

        if not password:
            messagebox.showwarning("Warning", "No password entered.")

        pass_entry.delete(0, tk.END)
        pass_entry.insert(0, password.translate(decrypter))

    chars = ' ' + string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
    key = chars

    # Determining the number of character shifts performed to the left
    left_shift = 5

    # Creating the secure password key
    for _ in range(left_shift):
        key = f"{key[1::]}{key[0]}"

    # Initializing the Password Encryption and Decryption window
    root = tk.Toplevel()
    root.title("Password Encrypter and Decrypter")
    root.geometry("600x250")
    root.config(bg=bg_colour)

    # Centralizing the GUI elements of the Password Encryption/Decryption window
    frame = tk.Frame(root)
    frame.configure(bg=bg_colour)
    frame.pack()

    label = tk.Label(frame, text="🌟 Enter the password you wish to encrypt:", font=("Cascadia Code", 15), fg=txt_colour,
                     bg=bg_colour)
    label.pack(pady=2, anchor=tk.W)

    pass_entry = tk.Entry(frame, width=40,font=("Comic Sans MS", 15))
    pass_entry.pack(pady=13)

    encrypt_button = tk.Button(frame, text="Encrypt", font=("Arial", 15), command=encrypt, padx=5, pady=3, fg=bg_colour,
                              bg='#33B828',relief="raised",bd="10")
    encrypt_button.pack(pady=10)

    decrypt_button = tk.Button(frame, text="Decrypt", font=("Arial", 15), command=decrypt, padx=5, pady=3, fg=bg_colour,
                               bg='#33B828',relief="raised",bd="10")
    decrypt_button.pack(pady=10)

    root.mainloop()


label_main = tk.Label(frame_main, text="--- WELCOME TO THE PASSWORD HUB! ---", font=("Cascadia Code", 14), fg=txt_colour,
                 bg=bg_colour)
label_main.pack(pady=10)

# Extra label for spacing purposes
space_label = tk.Label(frame_main, text='', bg=bg_colour)
space_label.pack()

button_1 = tk.Button(frame_main, text='Password Strength Checker', font=("Arial", 11), command=password_strength_checker,
                     padx=5, pady=10, fg=bg_colour, bg='#33B828',relief="raised",bd="10")
button_1.pack(pady=2)

button_2 = tk.Button(frame_main, text='Password Encrypter and Decrypter', font=("Arial", 11),
                     command=password_encrypter_decrypter, padx=5, pady=10, fg=bg_colour, bg='#33B828',relief="raised",bd="10")
button_2.pack(pady=2)

button_3 = tk.Button(frame_main, text='Exit', font=("Arial", 11), command=confirm_exit, padx=5, pady=10, fg=bg_colour,
                     bg='#33B828',relief="raised",bd="10")
button_3.pack(pady=2)


root_main.mainloop()
