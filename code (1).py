import tkinter as tk
from tkinter import ttk, messagebox
import os

# --- Backend Logic ---

FILE_NAME = "students.txt"
ENCRYPTION_KEY = 'S'  # Simple XOR key

def encrypt_decrypt(data):
    """Simple XOR encryption/decryption logic."""
    # In Python, strings are immutable, so we build a new one.
    # We maintain the same logic: char ^ key
    # Note: This produces characters that might not be printable or safe for text files 
    # if we just write them directly without encoding, but to stick close to the C++ logic
    # we will try to keep it simple. However, writing raw binary chars to a text file 
    # can get messy with encoding (utf-8). 
    # To ensure it works robustly in Python file I/O, we'll iterate char codes.
    
    result = []
    for char in data:
        # XOR the ordinal value of the char with the ordinal of the key
        encrypted_char = chr(ord(char) ^ ord(ENCRYPTION_KEY))
        result.append(encrypted_char)
    return "".join(result)

def save_record(student_id, name, branch):
    data_string = f"{student_id}|{name}|{branch}"
    encrypted_data = encrypt_decrypt(data_string)
    
    try:
        # Use 'a' for append, encoding='utf-8' to handle potential special chars
        with open(FILE_NAME, "a", encoding="utf-8") as f:
            f.write(encrypted_data + "\n")
        return True, "Record Added Successfully!"
    except Exception as e:
        return False, f"Error saving record: {e}"

def load_records():
    records = []
    if not os.path.exists(FILE_NAME):
        return records

    try:
        with open(FILE_NAME, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip('\n') # Remove newline char only
                if not line:
                    continue
                
                decrypted = encrypt_decrypt(line)
                parts = decrypted.split('|')
                if len(parts) >= 3:
                    records.append({
                        "id": parts[0],
                        "name": parts[1],
                        "branch": parts[2],
                        "original_line": line # Store for deletion reference if needed
                    })
    except Exception as e:
        messagebox.showerror("Error", f"Could not read file: {e}")
        
    return records

def delete_record_by_id(target_id):
    records = []
    deleted = False
    
    if not os.path.exists(FILE_NAME):
        return False, "File not found."

    try:
        with open(FILE_NAME, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        with open(FILE_NAME, "w", encoding="utf-8") as f:
            for line in lines:
                line_content = line.strip('\n')
                if not line_content:
                    continue
                    
                decrypted = encrypt_decrypt(line_content)
                parts = decrypted.split('|')
                
                if len(parts) >= 1 and parts[0] == target_id:
                    deleted = True
                    # Do not write this line back
                else:
                    f.write(line)
                    
        if deleted:
            return True, "Record Deleted Successfully!"
        else:
            return False, "Record Not Found!"
            
    except Exception as e:
        return False, f"Error deleting record: {e}"

# --- GUI Implementation ---

class StudentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Student Record Management")
        self.root.geometry("600x450")
        
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = tk.Label(root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Main Container - Tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)
        
        # --- Tab 1: Add Record ---
        self.tab_add = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_add, text='  Add Record  ')
        self.setup_add_tab()
        
        # --- Tab 2: View / Search / Delete ---
        self.tab_view = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_view, text='  View & Manage Records  ')
        self.setup_view_tab()

    def setup_add_tab(self):
        frame = ttk.Frame(self.tab_add, padding="20")
        frame.pack(expand=True)
        
        # Title
        ttk.Label(frame, text="Add New Student", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Inputs
        ttk.Label(frame, text="Student ID:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.entry_id = ttk.Entry(frame, width=30)
        self.entry_id.grid(row=1, column=1, pady=5, padx=10)
        
        ttk.Label(frame, text="Student Name:").grid(row=2, column=0, sticky=tk.E, pady=5)
        self.entry_name = ttk.Entry(frame, width=30)
        self.entry_name.grid(row=2, column=1, pady=5, padx=10)
        
        ttk.Label(frame, text="Branch:").grid(row=3, column=0, sticky=tk.E, pady=5)
        self.entry_branch = ttk.Entry(frame, width=30)
        self.entry_branch.grid(row=3, column=1, pady=5, padx=10)
        
        # Submit Button
        btn_submit = ttk.Button(frame, text="Save Record", command=self.handle_add_record)
        btn_submit.grid(row=4, column=0, columnspan=2, pady=20, ipadx=20)
        
    def setup_view_tab(self):
        # Top Control Panel (Search/Delete)
        control_frame = ttk.Frame(self.tab_view, padding="10")
        control_frame.pack(fill=tk.X)
        
        ttk.Label(control_frame, text="Search ID:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        entry_search = ttk.Entry(control_frame, textvariable=self.search_var, width=15)
        entry_search.pack(side=tk.LEFT, padx=5)
        
        btn_search = ttk.Button(control_frame, text="Search", command=self.handle_search)
        btn_search.pack(side=tk.LEFT, padx=5)
        
        btn_refresh = ttk.Button(control_frame, text="Refresh All", command=self.refresh_table)
        btn_refresh.pack(side=tk.LEFT, padx=5)
        
        btn_delete = ttk.Button(control_frame, text="Delete Selected", command=self.handle_delete_selected)
        btn_delete.pack(side=tk.RIGHT, padx=5)

        # Table (Treeview)
        columns = ("id", "name", "branch")
        self.tree = ttk.Treeview(self.tab_view, columns=columns, show='headings')
        
        self.tree.heading("id", text="Student ID")
        self.tree.heading("name", text="Name")
        self.tree.heading("branch", text="Branch")
        
        self.tree.column("id", width=100, anchor=tk.CENTER)
        self.tree.column("name", width=250, anchor=tk.W)
        self.tree.column("branch", width=150, anchor=tk.CENTER)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.tab_view, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Initial Load
        self.refresh_table()

    def handle_add_record(self):
        s_id = self.entry_id.get().strip()
        name = self.entry_name.get().strip()
        branch = self.entry_branch.get().strip()
        
        if not s_id or not name or not branch:
            messagebox.showwarning("Validation Error", "All fields are required!")
            return
            
        success, msg = save_record(s_id, name, branch)
        if success:
            self.status_var.set(msg)
            messagebox.showinfo("Success", msg)
            # Clear inputs
            self.entry_id.delete(0, tk.END)
            self.entry_name.delete(0, tk.END)
            self.entry_branch.delete(0, tk.END)
            # Refresh list
            self.refresh_table()
        else:
            self.status_var.set("Error adding record")
            messagebox.showerror("Error", msg)

    def refresh_table(self):
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        records = load_records()
        for r in records:
            self.tree.insert("", tk.END, values=(r['id'], r['name'], r['branch']))
            
        self.status_var.set(f"Loaded {len(records)} records.")

    def handle_search(self):
        search_id = self.search_var.get().strip()
        if not search_id:
            self.refresh_table()
            return
            
        # Filter visually
        found = False
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        records = load_records()
        for r in records:
            if r['id'] == search_id:
                self.tree.insert("", tk.END, values=(r['id'], r['name'], r['branch']))
                found = True
        
        if found:
            self.status_var.set(f"Record found for ID: {search_id}")
        else:
            self.status_var.set(f"No record found for ID: {search_id}")
            messagebox.showinfo("Search Result", f"No student found with ID: {search_id}")
            self.refresh_table() # Restore list

    def handle_delete_selected(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Selection", "Please select a record from the list to delete.")
            return
            
        # Get ID from selected row
        item_values = self.tree.item(selected_item)['values']
        # values comes out as tuple, e.g. (101, 'Name', 'Branch')
        # Note: Tkinter Treeview values might be converted to strings or ints depending on input,
        # but safely accessing index 0 usually gives us the ID.
        target_id = str(item_values[0])
        
        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete Student ID: {target_id}?")
        if confirm:
            success, msg = delete_record_by_id(target_id)
            if success:
                self.status_var.set(msg)
                messagebox.showinfo("Success", msg)
                self.refresh_table()
            else:
                self.status_var.set("Error deleting record")
                messagebox.showerror("Error", msg)

if __name__ == "__main__":
    print("Starting application...")
    try:
        root = tk.Tk()
        print("Root created")
        app = StudentApp(root)
        print("App initialized")
        root.mainloop()
        print("Mainloop exited")
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
