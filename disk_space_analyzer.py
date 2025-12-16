import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import threading
from datetime import datetime, timedelta
import json
import shutil
import uuid
import hashlib
from collections import defaultdict
import platform


class DiskSpaceAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("DiskTective")
        self.root.geometry("1200x800")

        self.scanning = False
        self.current_path = os.path.expanduser("~")
        self.files_data = []
        self.folders_data = []
        self.duplicates_data = []
        self.age_categories_data = {}

        self.trash_folder = os.path.join(os.path.expanduser("~"), ".disk_analyzer_trash")
        self.trash_metadata = os.path.join(self.trash_folder, "trash_metadata.json")
        self.ensure_trash_folder()

        self.setup_ui()

    def setup_ui(self):
        title_frame = ttk.Frame(self.root, padding="10")
        title_frame.pack(fill=tk.X)

        ttk.Label(title_frame, text="DiskTective",
                  font=("Arial", 18, "bold")).pack(side=tk.LEFT)

       # ttk.Label(title_frame, text="Pro Edition",
                 # font=("Arial", 10, "italic"), foreground="blue").pack(side=tk.LEFT, padx=10)

        control_frame = ttk.LabelFrame(self.root, text="Scan Settings", padding="15")
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        path_frame = ttk.Frame(control_frame)
        path_frame.pack(fill=tk.X, pady=5)

        ttk.Label(path_frame, text="Scan Path:", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

        self.path_entry = ttk.Entry(path_frame, width=60, font=("Arial", 10))
        self.path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.path_entry.insert(0, self.current_path)

        ttk.Button(path_frame, text="Browse", command=self.browse_folder, width=12).pack(side=tk.LEFT, padx=5)

        quick_frame = ttk.Frame(control_frame)
        quick_frame.pack(fill=tk.X, pady=10)

        ttk.Label(quick_frame, text="Quick Scan:", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(quick_frame, text="Home",
                   command=lambda: self.set_path(os.path.expanduser("~")), width=12).pack(side=tk.LEFT, padx=3)
        ttk.Button(quick_frame, text="Downloads",
                   command=lambda: self.set_path(os.path.join(os.path.expanduser("~"), "Downloads")), width=12).pack(
            side=tk.LEFT, padx=3)
        ttk.Button(quick_frame, text="Documents",
                   command=lambda: self.set_path(os.path.join(os.path.expanduser("~"), "Documents")), width=12).pack(
            side=tk.LEFT, padx=3)
        ttk.Button(quick_frame, text="Desktop",
                   command=lambda: self.set_path(os.path.join(os.path.expanduser("~"), "Desktop")), width=12).pack(
            side=tk.LEFT, padx=3)

        scan_frame = ttk.Frame(control_frame)
        scan_frame.pack(fill=tk.X, pady=5)

        self.scan_btn = ttk.Button(scan_frame, text="Deep Scan", command=self.start_scan, width=20)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(scan_frame, text="Stop", command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(scan_frame, text="Find Duplicates", command=self.find_duplicates, width=18).pack(side=tk.LEFT,
                                                                                                    padx=5)

        self.status_label = ttk.Label(scan_frame, text="Ready to scan", font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=20)

        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(10, 0))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        disk_health_frame = ttk.Frame(self.notebook)
        self.notebook.add(disk_health_frame, text="Disk Health")
        self.setup_disk_health_tab(disk_health_frame)

        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Folder Overview")
        self.setup_folder_dashboard_tab(dashboard_frame)

        duplicates_frame = ttk.Frame(self.notebook)
        self.notebook.add(duplicates_frame, text="Duplicates")
        self.setup_duplicates_tab(duplicates_frame)

        age_frame = ttk.Frame(self.notebook)
        self.notebook.add(age_frame, text="File Age")
        self.setup_age_tab(age_frame)

        files_frame = ttk.Frame(self.notebook)
        self.notebook.add(files_frame, text="Large Files")
        self.setup_files_tab(files_frame)

        folders_frame = ttk.Frame(self.notebook)
        self.notebook.add(folders_frame, text="Folders")
        self.setup_folders_tab(folders_frame)

        types_frame = ttk.Frame(self.notebook)
        self.notebook.add(types_frame, text="File Types")
        self.setup_types_tab(types_frame)

        trash_frame = ttk.Frame(self.notebook)
        self.notebook.add(trash_frame, text="Recycle Bin")
        self.setup_trash_tab(trash_frame)

        stats_frame = ttk.Frame(self.root, padding="10")
        stats_frame.pack(fill=tk.X)

        self.stats_label = ttk.Label(stats_frame, text="", font=("Arial", 10, "bold"))
        self.stats_label.pack()

    def setup_disk_health_tab(self, parent):
        header_frame = ttk.Frame(parent, padding="15")
        header_frame.pack(fill=tk.X)

        ttk.Label(header_frame, text="Overall Disk Health",
                  font=("Arial", 14, "bold")).pack(anchor=tk.W)
        ttk.Label(header_frame, text="System-wide disk usage and health monitoring",
                  font=("Arial", 9), foreground="gray").pack(anchor=tk.W)

        content_frame = ttk.Frame(parent, padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True)

        disk_frame = ttk.LabelFrame(content_frame, text="Disk Information", padding="15")
        disk_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.disk_total_label = ttk.Label(disk_frame, text="Total: -", font=("Arial", 12))
        self.disk_total_label.pack(anchor=tk.W, pady=5)

        self.disk_used_label = ttk.Label(disk_frame, text="Used: -", font=("Arial", 12))
        self.disk_used_label.pack(anchor=tk.W, pady=5)

        self.disk_free_label = ttk.Label(disk_frame, text="Free: -", font=("Arial", 12))
        self.disk_free_label.pack(anchor=tk.W, pady=5)

        ttk.Label(disk_frame, text="Disk Usage:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(10, 5))
        self.disk_usage_bar = ttk.Progressbar(disk_frame, length=400, mode='determinate')
        self.disk_usage_bar.pack(fill=tk.X, pady=5)

        self.disk_percent_label = ttk.Label(disk_frame, text="0%", font=("Arial", 11, "bold"))
        self.disk_percent_label.pack(anchor=tk.W)

        ttk.Label(disk_frame, text="Health Status:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(15, 5))
        self.health_label = ttk.Label(disk_frame, text="Excellent",
                                      font=("Arial", 12, "bold"), foreground="green")
        self.health_label.pack(anchor=tk.W)

        ttk.Separator(disk_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        ttk.Label(disk_frame, text="Recommendations:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.health_recommendations = ttk.Label(disk_frame, text="Disk is healthy",
                                                font=("Arial", 9), foreground="gray")
        self.health_recommendations.pack(anchor=tk.W, pady=5)

        self.update_disk_health()

    def setup_folder_dashboard_tab(self, parent):
        header_frame = ttk.Frame(parent, padding="15")
        header_frame.pack(fill=tk.X)

        ttk.Label(header_frame, text="Scanned Folder Overview",
                  font=("Arial", 14, "bold")).pack(anchor=tk.W)
        ttk.Label(header_frame, text="Statistics for the currently scanned folder",
                  font=("Arial", 9), foreground="gray").pack(anchor=tk.W)

        folder_info_frame = ttk.Frame(parent, padding="10")
        folder_info_frame.pack(fill=tk.X)

        ttk.Label(folder_info_frame, text="Current Folder:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.current_folder_label = ttk.Label(folder_info_frame, text=self.current_path,
                                              font=("Arial", 10), foreground="blue")
        self.current_folder_label.pack(anchor=tk.W, pady=5)

        content_frame = ttk.Frame(parent, padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.LabelFrame(content_frame, text="Folder Statistics", padding="15")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.folder_total_size_label = ttk.Label(left_frame, text="Total Size: -", font=("Arial", 11))
        self.folder_total_size_label.pack(anchor=tk.W, pady=5)

        self.folder_files_label = ttk.Label(left_frame, text="Total Files: -", font=("Arial", 11))
        self.folder_files_label.pack(anchor=tk.W, pady=5)

        self.folder_folders_label = ttk.Label(left_frame, text="Total Folders: -", font=("Arial", 11))
        self.folder_folders_label.pack(anchor=tk.W, pady=5)

        self.folder_largest_file_label = ttk.Label(left_frame, text="Largest File: -", font=("Arial", 11))
        self.folder_largest_file_label.pack(anchor=tk.W, pady=5)

        self.folder_avg_size_label = ttk.Label(left_frame, text="Avg File Size: -", font=("Arial", 11))
        self.folder_avg_size_label.pack(anchor=tk.W, pady=5)

        ttk.Separator(left_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

        self.folder_duplicates_label = ttk.Label(left_frame, text="Duplicate Files: -", font=("Arial", 11))
        self.folder_duplicates_label.pack(anchor=tk.W, pady=5)

        self.folder_old_files_label = ttk.Label(left_frame, text="Old Files (>1yr): -", font=("Arial", 11))
        self.folder_old_files_label.pack(anchor=tk.W, pady=5)

        self.folder_large_files_label = ttk.Label(left_frame, text="Large Files (>100MB): -", font=("Arial", 11))
        self.folder_large_files_label.pack(anchor=tk.W, pady=5)

        right_frame = ttk.LabelFrame(content_frame, text="Quick Actions", padding="15")
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)

        ttk.Button(right_frame, text="Find Duplicates",
                   command=self.find_duplicates, width=20).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Analyze File Ages",
                   command=self.analyze_file_ages, width=20).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Find Large Files (>100MB)",
                   command=self.quick_find_large, width=20).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Find Old Files (>1yr)",
                   command=self.quick_find_old, width=20).pack(fill=tk.X, pady=5)

        ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        ttk.Label(right_frame, text="File Type Breakdown:",
                  font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))

        self.top_types_frame = ttk.Frame(right_frame)
        self.top_types_frame.pack(fill=tk.BOTH, expand=True)

    def setup_duplicates_tab(self, parent):
        header_frame = ttk.Frame(parent, padding="10")
        header_frame.pack(fill=tk.X)

        ttk.Label(header_frame, text="Duplicate File Finder",
                  font=("Arial", 14, "bold")).pack(side=tk.LEFT)

        ttk.Button(header_frame, text="Find Duplicates", command=self.find_duplicates,
                   width=18).pack(side=tk.RIGHT, padx=5)

        info_frame = ttk.Frame(parent, padding="5")
        info_frame.pack(fill=tk.X)
        ttk.Label(info_frame,
                  text="Each duplicate file is shown separately. Files with the same hash are duplicates of each other.",
                  font=("Arial", 9), foreground="gray").pack()

        control_frame = ttk.Frame(parent, padding="5")
        control_frame.pack(fill=tk.X)

        ttk.Button(control_frame, text="Delete Selected", command=self.delete_duplicate,
                   width=18).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Open Location", command=self.open_duplicate_location,
                   width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Delete All But First",
                   command=self.delete_duplicates_keep_first, width=20).pack(side=tk.LEFT, padx=5)

        self.duplicates_info_label = ttk.Label(control_frame, text="", font=("Arial", 9, "bold"))
        self.duplicates_info_label.pack(side=tk.RIGHT, padx=10)

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ('Hash', 'Size', 'Group', 'Name', 'Path', 'Waste')
        self.duplicates_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)

        self.duplicates_tree.heading('Hash', text='Hash (MD5)')
        self.duplicates_tree.heading('Size', text='File Size')
        self.duplicates_tree.heading('Group', text='Group')
        self.duplicates_tree.heading('Name', text='File Name')
        self.duplicates_tree.heading('Path', text='Full Path')
        self.duplicates_tree.heading('Waste', text='Wasted Space')

        self.duplicates_tree.column('Hash', width=100)
        self.duplicates_tree.column('Size', width=100)
        self.duplicates_tree.column('Group', width=120)
        self.duplicates_tree.column('Name', width=200)
        self.duplicates_tree.column('Path', width=350)
        self.duplicates_tree.column('Waste', width=100)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.duplicates_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.duplicates_tree.xview)
        self.duplicates_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.duplicates_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

    def setup_age_tab(self, parent):
        header_frame = ttk.Frame(parent, padding="15")
        header_frame.pack(fill=tk.X)

        ttk.Label(header_frame, text="File Age Analysis",
                  font=("Arial", 14, "bold")).pack(anchor=tk.W)
        ttk.Label(header_frame, text="Find old files that haven't been modified in months or years",
                  font=("Arial", 9), foreground="gray").pack(anchor=tk.W)

        content_frame = ttk.Frame(parent, padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True)

        categories = [
            ("Last 30 days", "30days", "green"),
            ("1-3 months", "3months", "blue"),
            ("3-6 months", "6months", "orange"),
            ("6-12 months", "1year", "darkorange"),
            ("1-2 years", "2years", "red"),
            ("Over 2 years", "old", "darkred"),
        ]

        for label, key, color in categories:
            frame = ttk.LabelFrame(content_frame, text=label, padding="10")
            frame.pack(fill=tk.X, pady=5)

            count_label = ttk.Label(frame, text="Files: -", font=("Arial", 10))
            count_label.pack(anchor=tk.W)

            size_label = ttk.Label(frame, text="Size: -", font=("Arial", 10))
            size_label.pack(anchor=tk.W)

            progress = ttk.Progressbar(frame, length=400, mode='determinate')
            progress.pack(fill=tk.X, pady=5)

            btn = ttk.Button(frame, text=f"View Files",
                             command=lambda k=key, l=label: self.view_age_category(k, l))
            btn.pack(anchor=tk.W)

            setattr(self, f"{key}_count_label", count_label)
            setattr(self, f"{key}_size_label", size_label)
            setattr(self, f"{key}_progress", progress)

        ttk.Button(content_frame, text="Analyze File Ages", command=self.analyze_file_ages,
                   width=25).pack(pady=15)

    def setup_files_tab(self, parent):
        control_frame = ttk.Frame(parent, padding="5")
        control_frame.pack(fill=tk.X)

        ttk.Button(control_frame, text="Move to...", command=self.move_file, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Button(control_frame, text="Copy to...", command=self.copy_file, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Button(control_frame, text="Delete", command=self.delete_file, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Button(control_frame, text="Open Folder", command=self.open_file_location, width=15).pack(side=tk.LEFT,
                                                                                                      padx=3)
        ttk.Button(control_frame, text="Export List", command=self.export_files, width=15).pack(side=tk.LEFT, padx=3)

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ('Size', 'Name', 'Path', 'Modified')
        self.files_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)

        self.files_tree.heading('Size', text='Size')
        self.files_tree.heading('Name', text='File Name')
        self.files_tree.heading('Path', text='Location')
        self.files_tree.heading('Modified', text='Last Modified')

        self.files_tree.column('Size', width=100)
        self.files_tree.column('Name', width=250)
        self.files_tree.column('Path', width=400)
        self.files_tree.column('Modified', width=150)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.files_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.files_tree.xview)
        self.files_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.files_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.files_tree.bind('<Double-1>', lambda e: self.open_file_location())

    def setup_folders_tab(self, parent):
        control_frame = ttk.Frame(parent, padding="5")
        control_frame.pack(fill=tk.X)

        ttk.Button(control_frame, text="Move to...", command=self.move_folder, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Button(control_frame, text="Copy to...", command=self.copy_folder, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Button(control_frame, text="Delete", command=self.delete_folder, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Button(control_frame, text="Open Folder", command=self.open_folder_location, width=15).pack(side=tk.LEFT,
                                                                                                        padx=3)
        ttk.Button(control_frame, text="Scan This", command=self.scan_selected_folder, width=15).pack(side=tk.LEFT,
                                                                                                      padx=3)

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ('Size', 'Name', 'Path', 'Files')
        self.folders_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)

        self.folders_tree.heading('Size', text='Size')
        self.folders_tree.heading('Name', text='Folder Name')
        self.folders_tree.heading('Path', text='Location')
        self.folders_tree.heading('Files', text='File Count')

        self.folders_tree.column('Size', width=100)
        self.folders_tree.column('Name', width=250)
        self.folders_tree.column('Path', width=400)
        self.folders_tree.column('Files', width=100)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.folders_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.folders_tree.xview)
        self.folders_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.folders_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.folders_tree.bind('<Double-1>', lambda e: self.open_folder_location())

    def setup_types_tab(self, parent):
        table_frame = ttk.Frame(parent, padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('Extension', 'Count', 'Total Size', 'Avg Size')
        self.types_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)

        self.types_tree.heading('Extension', text='File Type')
        self.types_tree.heading('Count', text='File Count')
        self.types_tree.heading('Total Size', text='Total Size')
        self.types_tree.heading('Avg Size', text='Average Size')

        self.types_tree.column('Extension', width=150)
        self.types_tree.column('Count', width=150)
        self.types_tree.column('Total Size', width=150)
        self.types_tree.column('Avg Size', width=150)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.types_tree.yview)
        self.types_tree.configure(yscrollcommand=vsb.set)

        self.types_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_trash_tab(self, parent):
        control_frame = ttk.Frame(parent, padding="5")
        control_frame.pack(fill=tk.X)

        ttk.Button(control_frame, text="Restore Selected", command=self.restore_from_trash, width=18).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Delete Permanently", command=self.delete_permanently, width=18).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Empty Recycle Bin", command=self.empty_trash, width=18).pack(side=tk.LEFT,
                                                                                                     padx=5)
        ttk.Button(control_frame, text="Refresh", command=self.load_trash, width=12).pack(side=tk.LEFT, padx=5)

        self.trash_size_label = ttk.Label(control_frame, text="", font=("Arial", 10, "bold"))
        self.trash_size_label.pack(side=tk.RIGHT, padx=10)

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ('Size', 'Name', 'Original Location', 'Deleted Date')
        self.trash_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)

        self.trash_tree.heading('Size', text='Size')
        self.trash_tree.heading('Name', text='File/Folder Name')
        self.trash_tree.heading('Original Location', text='Original Location')
        self.trash_tree.heading('Deleted Date', text='Deleted Date')

        self.trash_tree.column('Size', width=100)
        self.trash_tree.column('Name', width=250)
        self.trash_tree.column('Original Location', width=400)
        self.trash_tree.column('Deleted Date', width=150)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.trash_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.trash_tree.xview)
        self.trash_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.trash_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        info_frame = ttk.Frame(parent, padding="10")
        info_frame.pack(fill=tk.X)

        info_text = "Files moved to Recycle Bin can be restored to their original location or permanently deleted."
        ttk.Label(info_frame, text=info_text, font=("Arial", 9), foreground="gray").pack()

        self.load_trash()

    def update_disk_health(self):
        try:
            path = self.current_path

            if platform.system() == 'Windows':
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(path),
                    None,
                    ctypes.pointer(total_bytes),
                    ctypes.pointer(free_bytes)
                )
                total = total_bytes.value
                free = free_bytes.value
            else:
                stat = os.statvfs(path)
                total = stat.f_blocks * stat.f_frsize
                free = stat.f_bavail * stat.f_frsize

            used = total - free
            percent_used = (used / total * 100) if total > 0 else 0

            self.disk_total_label.config(text=f"Total: {self.format_bytes(total)}")
            self.disk_used_label.config(text=f"Used: {self.format_bytes(used)}")
            self.disk_free_label.config(text=f"Free: {self.format_bytes(free)}")

            self.disk_usage_bar['value'] = percent_used
            self.disk_percent_label.config(text=f"{percent_used:.1f}% used")

            if percent_used > 90:
                self.health_label.config(text="Critical", foreground="red")
                self.disk_percent_label.config(foreground="red")
                self.health_recommendations.config(
                    text="WARNING: Disk is almost full! Delete unnecessary files immediately.",
                    foreground="red"
                )
            elif percent_used > 75:
                self.health_label.config(text="Warning", foreground="orange")
                self.disk_percent_label.config(foreground="orange")
                self.health_recommendations.config(
                    text="WARNING: Disk space is running low. Consider cleaning up files.",
                    foreground="orange"
                )
            elif percent_used > 50:
                self.health_label.config(text="Good", foreground="blue")
                self.disk_percent_label.config(foreground="blue")
                self.health_recommendations.config(
                    text="Disk is healthy. Monitor usage regularly.",
                    foreground="blue"
                )
            else:
                self.health_label.config(text="Excellent", foreground="green")
                self.disk_percent_label.config(foreground="green")
                self.health_recommendations.config(
                    text="Disk is in excellent condition!",
                    foreground="green"
                )

        except Exception as e:
            print(f"Error updating disk health: {e}")

    def update_folder_dashboard(self):
        if not self.files_data:
            return

        self.current_folder_label.config(text=self.current_path)

        total_size = sum(f['size'] for f in self.files_data)
        self.folder_total_size_label.config(text=f"Total Size: {self.format_bytes(total_size)}")

        self.folder_files_label.config(text=f"Total Files: {len(self.files_data):,}")

        folder_count = len(self.folders_data) if self.folders_data else 0
        self.folder_folders_label.config(text=f"Total Folders: {folder_count:,}")

        if self.files_data:
            largest = max(self.files_data, key=lambda x: x['size'])
            self.folder_largest_file_label.config(
                text=f"Largest File: {self.format_bytes(largest['size'])} ({largest['name'][:30]}...)"
            )

            avg_size = sum(f['size'] for f in self.files_data) / len(self.files_data)
            self.folder_avg_size_label.config(text=f"Avg File Size: {self.format_bytes(avg_size)}")

        duplicate_count = len(self.duplicates_data) if self.duplicates_data else 0
        self.folder_duplicates_label.config(text=f"Duplicate Files: {duplicate_count} sets found")

        now = datetime.now()
        old_files = [f for f in self.files_data if os.path.exists(f['path']) and
                     (now - datetime.fromtimestamp(os.path.getmtime(f['path']))).days > 365]
        old_size = sum(f['size'] for f in old_files)
        self.folder_old_files_label.config(
            text=f"Old Files (>1yr): {len(old_files):,} ({self.format_bytes(old_size)})"
        )

        large_files = [f for f in self.files_data if f['size'] > 100 * 1024 * 1024]
        large_size = sum(f['size'] for f in large_files)
        self.folder_large_files_label.config(
            text=f"Large Files (>100MB): {len(large_files):,} ({self.format_bytes(large_size)})"
        )

        self.update_top_file_types()

    def update_top_file_types(self):
        for widget in self.top_types_frame.winfo_children():
            widget.destroy()

        if not self.files_data:
            return

        file_types = {}
        for file_data in self.files_data:
            ext = os.path.splitext(file_data['name'])[1].lower() or 'No Extension'
            if ext not in file_types:
                file_types[ext] = {'count': 0, 'size': 0}
            file_types[ext]['count'] += 1
            file_types[ext]['size'] += file_data['size']

        sorted_types = sorted(file_types.items(), key=lambda x: x[1]['size'], reverse=True)

        for ext, data in sorted_types[:5]:
            type_frame = ttk.Frame(self.top_types_frame)
            type_frame.pack(fill=tk.X, pady=2)

            ttk.Label(type_frame, text=f"{ext}:", font=("Arial", 9, "bold")).pack(side=tk.LEFT)
            ttk.Label(type_frame, text=f"{self.format_bytes(data['size'])} ({data['count']} files)",
                      font=("Arial", 9)).pack(side=tk.RIGHT)

    def find_duplicates(self):
        if not self.files_data:
            messagebox.showinfo("No Data", "Please scan a directory first!")
            return

        self.status_label.config(text="Finding duplicates...")
        self.progress.start()

        thread = threading.Thread(target=self._find_duplicates_thread, daemon=True)
        thread.start()

    def _find_duplicates_thread(self):
        try:
            hash_map = defaultdict(list)

            for file_data in self.files_data:
                try:
                    filepath = file_data['path']
                    if os.path.exists(filepath) and os.path.isfile(filepath):
                        if file_data['size'] < 100 * 1024 * 1024:
                            file_hash = self.calculate_file_hash(filepath)
                            hash_map[file_hash].append(file_data)
                except:
                    pass

            duplicates = {h: files for h, files in hash_map.items() if len(files) > 1}

            self.root.after(0, lambda: self.display_duplicates(duplicates))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Error finding duplicates: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.status_label.config(text="Duplicate search complete"))

    def calculate_file_hash(self, filepath, algorithm='md5'):
        hash_obj = hashlib.md5()

        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def display_duplicates(self, duplicates):
        for item in self.duplicates_tree.get_children():
            self.duplicates_tree.delete(item)

        total_waste = 0
        duplicate_count = 0
        group_num = 1

        for file_hash, files in duplicates.items():
            if len(files) > 1:
                file_size = files[0]['size']
                wasted_space = file_size * (len(files) - 1)
                total_waste += wasted_space
                duplicate_count += len(files)

                for idx, file_data in enumerate(files):
                    group_indicator = f"Group {group_num} ({idx + 1}/{len(files)})"

                    self.duplicates_tree.insert('', tk.END, values=(
                        file_hash[:12] + "...",
                        self.format_bytes(file_size),
                        group_indicator,
                        file_data['name'],
                        file_data['path'],
                        self.format_bytes(wasted_space) if idx == 0 else "-"
                    ), tags=(file_hash, file_data['path']))

                self.duplicates_tree.insert('', tk.END, values=(
                    "─" * 10, "─" * 8, "─" * 12, "─" * 15, "─" * 25, "─" * 8
                ), tags=('separator',))

                group_num += 1

        self.duplicates_info_label.config(
            text=f"Found {len(duplicates)} duplicate sets ({duplicate_count} files) - "
                 f"Wasting {self.format_bytes(total_waste)}"
        )

        self.duplicates_data = duplicates

        self.update_folder_dashboard()

    def delete_duplicate(self):
        selection = self.duplicates_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a duplicate file to delete!")
            return

        item = self.duplicates_tree.item(selection[0])

        if 'separator' in self.duplicates_tree.item(selection[0])['tags']:
            messagebox.showinfo("Invalid Selection", "Please select a file, not a separator line.")
            return

        filepath = self.duplicates_tree.item(selection[0])['tags'][1]
        filename = item['values'][3]

        result = messagebox.askyesnocancel(
            "Confirm Delete",
            f"Move '{filename}' to Recycle Bin?\n\nPath: {filepath}\n\nClick 'Yes' to delete, 'No' to keep, or 'Cancel' to do nothing.",
            icon='warning'
        )

        if result is None:
            return
        elif result:
            if self.move_to_trash(filepath):
                self.duplicates_tree.delete(selection[0])
                messagebox.showinfo("Success", f"'{filename}' moved to Recycle Bin!")
                self.load_trash()

    def open_duplicate_location(self):
        selection = self.duplicates_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a duplicate file!")
            return

        if 'separator' in self.duplicates_tree.item(selection[0])['tags']:
            messagebox.showinfo("Invalid Selection", "Please select a file, not a separator line.")
            return

        filepath = self.duplicates_tree.item(selection[0])['tags'][1]
        folder = os.path.dirname(filepath)

        try:
            if os.name == 'nt':
                os.startfile(folder)
            elif os.name == 'posix':
                os.system(f'open "{folder}"')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder: {str(e)}")

    def delete_duplicates_keep_first(self):
        if not self.duplicates_data:
            messagebox.showinfo("No Duplicates", "No duplicate groups found. Run 'Find Duplicates' first!")
            return

        total_to_delete = sum(len(files) - 1 for files in self.duplicates_data.values())

        result = messagebox.askyesnocancel(
            "Confirm Mass Delete",
            f"This will move {total_to_delete} duplicate files to Recycle Bin.\n\n"
            f"The FIRST file in each group will be kept.\n\n"
            f"Click 'Yes' to proceed, 'No' to abort, or 'Cancel' to do nothing.",
            icon='warning'
        )

        if result is None:
            return
        elif result:
            deleted_count = 0
            for file_hash, files in self.duplicates_data.items():
                for file_data in files[1:]:
                    if self.move_to_trash(file_data['path']):
                        deleted_count += 1

            messagebox.showinfo("Complete", f"Moved {deleted_count} duplicate files to Recycle Bin!")
            self.load_trash()
            self.find_duplicates()

    def analyze_file_ages(self):
        if not self.files_data:
            messagebox.showinfo("No Data", "Please scan a directory first!")
            return

        now = datetime.now()
        self.age_categories_data = {
            '30days': [],
            '3months': [],
            '6months': [],
            '1year': [],
            '2years': [],
            'old': []
        }

        for file_data in self.files_data:
            try:
                filepath = file_data['path']
                if os.path.exists(filepath):
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    age_days = (now - mtime).days

                    if age_days <= 30:
                        self.age_categories_data['30days'].append(file_data)
                    elif age_days <= 90:
                        self.age_categories_data['3months'].append(file_data)
                    elif age_days <= 180:
                        self.age_categories_data['6months'].append(file_data)
                    elif age_days <= 365:
                        self.age_categories_data['1year'].append(file_data)
                    elif age_days <= 730:
                        self.age_categories_data['2years'].append(file_data)
                    else:
                        self.age_categories_data['old'].append(file_data)
            except:
                pass

        total_files = len(self.files_data)
        for key, files in self.age_categories_data.items():
            count = len(files)
            size = sum(f['size'] for f in files)
            percent = (count / total_files * 100) if total_files > 0 else 0

            getattr(self, f"{key}_count_label").config(text=f"Files: {count:,}")
            getattr(self, f"{key}_size_label").config(text=f"Size: {self.format_bytes(size)}")
            getattr(self, f"{key}_progress")['value'] = percent

        messagebox.showinfo("Complete", "File age analysis complete! Click 'View Files' buttons to see details.")

        self.update_folder_dashboard()

    def view_age_category(self, category, label):
        if category not in self.age_categories_data or not self.age_categories_data[category]:
            messagebox.showinfo("No Data",
                                f"No files found in category: {label}\n\nPlease run 'Analyze File Ages' first!")
            return

        files = self.age_categories_data[category]

        popup = tk.Toplevel(self.root)
        popup.title(f"Files - {label}")
        popup.geometry("900x600")

        header_frame = ttk.Frame(popup, padding="10")
        header_frame.pack(fill=tk.X)

        ttk.Label(header_frame, text=f"{label}",
                  font=("Arial", 14, "bold")).pack(side=tk.LEFT)

        ttk.Label(header_frame, text=f"{len(files)} files | {self.format_bytes(sum(f['size'] for f in files))}",
                  font=("Arial", 10)).pack(side=tk.RIGHT)

        table_frame = ttk.Frame(popup, padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('Size', 'Name', 'Path', 'Modified')
        tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)

        tree.heading('Size', text='Size')
        tree.heading('Name', text='File Name')
        tree.heading('Path', text='Location')
        tree.heading('Modified', text='Last Modified')

        tree.column('Size', width=100)
        tree.column('Name', width=200)
        tree.column('Path', width=400)
        tree.column('Modified', width=150)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        for file_data in sorted(files, key=lambda x: x['size'], reverse=True):
            tree.insert('', tk.END, values=(
                self.format_bytes(file_data['size']),
                file_data['name'],
                file_data['path'],
                file_data['modified']
            ))

        btn_frame = ttk.Frame(popup, padding="10")
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Close", command=popup.destroy, width=15).pack(side=tk.RIGHT)

    def quick_find_large(self):
        if self.files_data:
            large_files = [f for f in self.files_data if f['size'] > 100 * 1024 * 1024]
            messagebox.showinfo("Large Files",
                                f"Found {len(large_files)} files larger than 100MB\n"
                                f"Total size: {self.format_bytes(sum(f['size'] for f in large_files))}")

    def quick_find_old(self):
        if self.files_data:
            now = datetime.now()
            old_files = [f for f in self.files_data if os.path.exists(f['path']) and
                         (now - datetime.fromtimestamp(os.path.getmtime(f['path']))).days > 365]
            old_size = sum(f['size'] for f in old_files)
            messagebox.showinfo("Old Files",
                                f"Found {len(old_files)} files older than 1 year\n"
                                f"Total size: {self.format_bytes(old_size)}")

    def ensure_trash_folder(self):
        if not os.path.exists(self.trash_folder):
            os.makedirs(self.trash_folder)
        if not os.path.exists(self.trash_metadata):
            with open(self.trash_metadata, 'w') as f:
                json.dump({}, f)

    def load_trash_metadata(self):
        try:
            if os.path.exists(self.trash_metadata):
                with open(self.trash_metadata, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def save_trash_metadata(self, metadata):
        try:
            with open(self.trash_metadata, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            print(f"Error saving metadata: {e}")

    def load_trash(self):
        for item in self.trash_tree.get_children():
            self.trash_tree.delete(item)
        metadata = self.load_trash_metadata()
        total_size = 0
        for trash_id, info in metadata.items():
            trash_path = os.path.join(self.trash_folder, trash_id)
            if os.path.exists(trash_path):
                size = self.get_size(trash_path)
                total_size += size
                self.trash_tree.insert('', tk.END, values=(
                    self.format_bytes(size),
                    info['name'],
                    info['original_path'],
                    info['deleted_date']
                ), tags=(trash_id,))
        self.trash_size_label.config(text=f"Total: {self.format_bytes(total_size)} ({len(metadata)} items)")

    def get_size(self, path):
        if os.path.isfile(path):
            return os.path.getsize(path)
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except:
                    pass
        return total_size

    def move_to_trash(self, path):
        try:
            trash_id = str(uuid.uuid4())
            name = os.path.basename(path)
            is_folder = os.path.isdir(path)
            trash_path = os.path.join(self.trash_folder, trash_id)
            shutil.move(path, trash_path)
            metadata = self.load_trash_metadata()
            metadata[trash_id] = {
                'name': name,
                'original_path': path,
                'deleted_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'is_folder': is_folder
            }
            self.save_trash_metadata(metadata)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to move to trash: {str(e)}")
            return False

    def browse_folder(self):
        folder = filedialog.askdirectory(initialdir=self.current_path)
        if folder:
            self.set_path(folder)

    def set_path(self, path):
        self.current_path = path
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, path)
        self.update_disk_health()

    def start_scan(self):
        path = self.path_entry.get().strip()
        if not os.path.exists(path):
            messagebox.showerror("Error", "Path does not exist!")
            return
        if not os.path.isdir(path):
            messagebox.showerror("Error", "Path is not a directory!")
            return

        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_label.config(text="Scanning...")

        self.files_data = []
        self.folders_data = []
        self.duplicates_data = []
        self.age_categories_data = {}
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
        for item in self.folders_tree.get_children():
            self.folders_tree.delete(item)
        for item in self.types_tree.get_children():
            self.types_tree.delete(item)

        thread = threading.Thread(target=self.scan_directory, args=(path,), daemon=True)
        thread.start()

    def stop_scan(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_label.config(text="Scan stopped")

    def scan_directory(self, path):
        """Fixed scan_directory with proper folder size calculation"""
        total_size = 0
        file_count = 0
        file_types = {}
        all_folders = set()

        try:
            for root, dirs, files in os.walk(path):
                if not self.scanning:
                    break

                all_folders.add(root)

                for filename in files:
                    if not self.scanning:
                        break
                    try:
                        filepath = os.path.join(root, filename)
                        size = os.path.getsize(filepath)
                        modified = os.path.getmtime(filepath)

                        total_size += size
                        file_count += 1

                        self.files_data.append({
                            'size': size,
                            'name': filename,
                            'path': filepath,
                            'modified': datetime.fromtimestamp(modified).strftime('%Y-%m-%d %H:%M')
                        })

                        ext = os.path.splitext(filename)[1].lower() or 'No Extension'
                        if ext not in file_types:
                            file_types[ext] = {'count': 0, 'size': 0}
                        file_types[ext]['count'] += 1
                        file_types[ext]['size'] += size

                        if file_count % 100 == 0:
                            self.root.after(0, lambda fc=file_count, ts=total_size: self.status_label.config(
                                text=f"Scanning... {fc} files, {self.format_bytes(ts)}"))
                    except (PermissionError, FileNotFoundError):
                        pass

            if self.scanning:
                folder_sizes = self.calculate_folder_sizes(path, all_folders)
                folder_count = len(all_folders)
            else:
                folder_sizes = {}
                folder_count = 0

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", f"Error: {str(e)}"))
            folder_sizes = {}
            folder_count = 0

        self.root.after(0, lambda: self.display_results(total_size, file_count, folder_count, file_types, folder_sizes))

    def calculate_folder_sizes(self, base_path, all_folders):
        """Calculate total size for each folder including subdirectories"""
        folder_sizes = {}
        folder_file_counts = defaultdict(int)

        for file_data in self.files_data:
            filepath = file_data['path']
            size = file_data['size']
            current_dir = os.path.dirname(filepath)

            while current_dir in all_folders and current_dir.startswith(base_path):
                if current_dir not in folder_sizes:
                    folder_sizes[current_dir] = 0
                folder_sizes[current_dir] += size
                folder_file_counts[current_dir] += 1

                parent = os.path.dirname(current_dir)
                if parent == current_dir:
                    break
                current_dir = parent

        result = {}
        for folder_path in all_folders:
            result[folder_path] = {
                'size': folder_sizes.get(folder_path, 0),
                'files': folder_file_counts.get(folder_path, 0)
            }

        return result

    def display_results(self, total_size, file_count, folder_count, file_types, folder_sizes):
        self.files_data.sort(key=lambda x: x['size'], reverse=True)
        for file_data in self.files_data[:500]:
            self.files_tree.insert('', tk.END, values=(
                self.format_bytes(file_data['size']),
                file_data['name'],
                file_data['path'],
                file_data['modified']
            ))

        folder_list = []
        for folder_path, data in folder_sizes.items():
            folder_list.append({
                'path': folder_path,
                'size': data['size'],
                'files': data['files'],
                'name': os.path.basename(folder_path) or folder_path
            })

        folder_list.sort(key=lambda x: x['size'], reverse=True)
        self.folders_data = folder_list
        for folder_data in folder_list[:200]:
            self.folders_tree.insert('', tk.END, values=(
                self.format_bytes(folder_data['size']),
                folder_data['name'],
                folder_data['path'],
                folder_data['files']
            ))

        type_list = []
        for ext, data in file_types.items():
            avg_size = data['size'] / data['count'] if data['count'] > 0 else 0
            type_list.append({
                'ext': ext,
                'count': data['count'],
                'size': data['size'],
                'avg': avg_size
            })

        type_list.sort(key=lambda x: x['size'], reverse=True)
        for type_data in type_list:
            self.types_tree.insert('', tk.END, values=(
                type_data['ext'],
                type_data['count'],
                self.format_bytes(type_data['size']),
                self.format_bytes(type_data['avg'])
            ))

        stats = f"Total: {self.format_bytes(total_size)} | Files: {file_count:,} | Folders: {folder_count:,}"
        self.stats_label.config(text=stats)

        self.stop_scan()
        self.status_label.config(text=f"Scan complete! Found {file_count:,} files")

        self.update_disk_health()
        self.update_folder_dashboard()

    def format_bytes(self, bytes_value):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"

    def move_file(self):
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file!")
            return
        item = self.files_tree.item(selection[0])
        filepath = item['values'][2]
        filename = item['values'][1]
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File no longer exists!")
            return
        destination = filedialog.askdirectory(title="Select destination folder")
        if not destination:
            return
        try:
            dest_path = os.path.join(destination, filename)
            if os.path.exists(dest_path):
                if not messagebox.askyesno("File Exists",
                                           f"A file with the name '{filename}' already exists in the destination.\n\nOverwrite it?"):
                    return
                os.remove(dest_path)
            shutil.move(filepath, dest_path)
            self.files_tree.delete(selection[0])
            messagebox.showinfo("Success", f"'{filename}' moved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to move file: {str(e)}")

    def copy_file(self):
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file!")
            return
        item = self.files_tree.item(selection[0])
        filepath = item['values'][2]
        filename = item['values'][1]
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File no longer exists!")
            return
        destination = filedialog.askdirectory(title="Select destination folder")
        if not destination:
            return
        try:
            dest_path = os.path.join(destination, filename)
            if os.path.exists(dest_path):
                if not messagebox.askyesno("File Exists",
                                           f"A file with the name '{filename}' already exists in the destination.\n\nOverwrite it?"):
                    return
                os.remove(dest_path)
            shutil.copy2(filepath, dest_path)
            messagebox.showinfo("Success", f"'{filename}' copied successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy file: {str(e)}")

    def move_folder(self):
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a folder!")
            return
        item = self.folders_tree.item(selection[0])
        folder_path = item['values'][2]
        folder_name = item['values'][1]
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Folder no longer exists!")
            return
        destination = filedialog.askdirectory(title="Select destination folder")
        if not destination:
            return
        if destination.startswith(folder_path):
            messagebox.showerror("Error", "Cannot move a folder into itself or its subdirectories!")
            return
        try:
            dest_path = os.path.join(destination, folder_name)
            if os.path.exists(dest_path):
                if not messagebox.askyesno("Folder Exists",
                                           f"A folder with the name '{folder_name}' already exists in the destination.\n\nMerge/Overwrite it?"):
                    return
                shutil.rmtree(dest_path)
            shutil.move(folder_path, dest_path)
            self.folders_tree.delete(selection[0])
            messagebox.showinfo("Success", f"'{folder_name}' moved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to move folder: {str(e)}")

    def copy_folder(self):
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a folder!")
            return
        item = self.folders_tree.item(selection[0])
        folder_path = item['values'][2]
        folder_name = item['values'][1]
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Folder no longer exists!")
            return
        destination = filedialog.askdirectory(title="Select destination folder")
        if not destination:
            return
        if destination.startswith(folder_path):
            messagebox.showerror("Error", "Cannot copy a folder into itself or its subdirectories!")
            return
        try:
            dest_path = os.path.join(destination, folder_name)
            if os.path.exists(dest_path):
                if not messagebox.askyesno("Folder Exists",
                                           f"A folder with the name '{folder_name}' already exists in the destination.\n\nMerge/Overwrite it?"):
                    return
                shutil.rmtree(dest_path)
            shutil.copytree(folder_path, dest_path)
            messagebox.showinfo("Success", f"'{folder_name}' copied successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy folder: {str(e)}")

    def delete_file(self):
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file!")
            return
        item = self.files_tree.item(selection[0])
        filepath = item['values'][2]
        filename = item['values'][1]

        result = messagebox.askyesnocancel(
            "Move to Recycle Bin",
            f"Move this file to Recycle Bin?\n\n{filename}\n\nClick 'Yes' to delete, 'No' to keep, or 'Cancel'.",
            icon='warning'
        )

        if result is None:
            return
        elif result:
            if self.move_to_trash(filepath):
                self.files_tree.delete(selection[0])
                messagebox.showinfo("Success", f"'{filename}' moved to Recycle Bin!")
                self.load_trash()

    def delete_folder(self):
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a folder!")
            return
        item = self.folders_tree.item(selection[0])
        folder = item['values'][2]
        foldername = item['values'][1]
        file_count = item['values'][3]

        result = messagebox.askyesnocancel(
            "Move to Recycle Bin",
            f"Move this folder to Recycle Bin?\n\n{foldername}\n\nContains {file_count} files\n\nClick 'Yes' to delete, 'No' to keep, or 'Cancel'.",
            icon='warning'
        )

        if result is None:
            return
        elif result:
            if self.move_to_trash(folder):
                self.folders_tree.delete(selection[0])
                messagebox.showinfo("Success", f"'{foldername}' moved to Recycle Bin!")
                self.load_trash()

    def open_file_location(self):
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file!")
            return
        item = self.files_tree.item(selection[0])
        filepath = item['values'][2]
        folder = os.path.dirname(filepath)
        try:
            if os.name == 'nt':
                os.startfile(folder)
            elif os.name == 'posix':
                os.system(f'open "{folder}"')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder: {str(e)}")

    def open_folder_location(self):
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a folder!")
            return
        item = self.folders_tree.item(selection[0])
        folder = item['values'][2]
        try:
            if os.name == 'nt':
                os.startfile(folder)
            elif os.name == 'posix':
                os.system(f'open "{folder}"')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder: {str(e)}")

    def scan_selected_folder(self):
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a folder!")
            return
        item = self.folders_tree.item(selection[0])
        folder = item['values'][2]
        self.set_path(folder)
        self.start_scan()

    def restore_from_trash(self):
        selection = self.trash_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an item to restore!")
            return
        item = self.trash_tree.item(selection[0])
        trash_id = self.trash_tree.item(selection[0])['tags'][0]
        original_location = item['values'][2]
        name = item['values'][1]

        result = messagebox.askyesnocancel(
            "Restore",
            f"Restore '{name}' to:\n{original_location}?\n\nClick 'Yes' to restore, 'No' to cancel.",
            icon='question'
        )

        if result is None or not result:
            return

        try:
            trash_path = os.path.join(self.trash_folder, trash_id)
            original_dir = os.path.dirname(original_location)
            if not os.path.exists(original_dir):
                if messagebox.askyesno("Location Missing",
                                       f"Original location doesn't exist:\n{original_dir}\n\nRestore to Desktop instead?"):
                    original_location = os.path.join(os.path.expanduser("~"), "Desktop", name)
                else:
                    return
            if os.path.exists(original_location):
                if not messagebox.askyesno("File Exists",
                                           f"A file already exists at:\n{original_location}\n\nOverwrite it?"):
                    return
                if os.path.isdir(original_location):
                    shutil.rmtree(original_location)
                else:
                    os.remove(original_location)
            shutil.move(trash_path, original_location)
            metadata = self.load_trash_metadata()
            del metadata[trash_id]
            self.save_trash_metadata(metadata)
            messagebox.showinfo("Success", f"'{name}' restored successfully!")
            self.load_trash()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore: {str(e)}")

    def delete_permanently(self):
        selection = self.trash_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an item to delete!")
            return
        item = self.trash_tree.item(selection[0])
        trash_id = self.trash_tree.item(selection[0])['tags'][0]
        name = item['values'][1]

        result = messagebox.askyesnocancel(
            "Permanent Delete",
            f"WARNING: PERMANENTLY delete '{name}'?\n\nThis CANNOT be undone!\n\nClick 'Yes' to delete permanently, 'No' to keep in Recycle Bin, or 'Cancel'.",
            icon='warning'
        )

        if result is None:
            return
        elif result:
            try:
                trash_path = os.path.join(self.trash_folder, trash_id)
                if os.path.isdir(trash_path):
                    shutil.rmtree(trash_path)
                else:
                    os.remove(trash_path)
                metadata = self.load_trash_metadata()
                del metadata[trash_id]
                self.save_trash_metadata(metadata)
                messagebox.showinfo("Success", "Item permanently deleted!")
                self.load_trash()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete: {str(e)}")

    def empty_trash(self):
        metadata = self.load_trash_metadata()
        item_count = len(metadata)
        if item_count == 0:
            messagebox.showinfo("Empty", "Recycle Bin is already empty!")
            return

        result = messagebox.askyesnocancel(
            "Empty Recycle Bin",
            f"WARNING: PERMANENTLY delete ALL {item_count} items?\n\nThis CANNOT be undone!\n\nClick 'Yes' to empty, 'No' to keep, or 'Cancel'.",
            icon='warning'
        )

        if result is None:
            return
        elif result:
            try:
                for trash_id in list(metadata.keys()):
                    trash_path = os.path.join(self.trash_folder, trash_id)
                    if os.path.exists(trash_path):
                        if os.path.isdir(trash_path):
                            shutil.rmtree(trash_path)
                        else:
                            os.remove(trash_path)
                self.save_trash_metadata({})
                messagebox.showinfo("Success", f"Recycle Bin emptied! {item_count} items deleted.")
                self.load_trash()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to empty trash: {str(e)}")

    def export_files(self):
        if not self.files_data:
            messagebox.showwarning("No Data", "No files to export!")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"disk_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Size (Bytes)', 'Size', 'Name', 'Path', 'Modified'])
                    for file_data in self.files_data:
                        writer.writerow([
                            file_data['size'],
                            self.format_bytes(file_data['size']),
                            file_data['name'],
                            file_data['path'],
                            file_data['modified']
                        ])
                messagebox.showinfo("Success", f"Exported {len(self.files_data)} files!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")


def main():
    root = tk.Tk()
    app = DiskSpaceAnalyzer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
