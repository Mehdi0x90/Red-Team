# ZIP & RAR File Crack

* Requirements
1. A Linux-based system (John the Ripper is often used on Linux distributions)
2. John the Ripper software installed (download from the official website)
3. A password-protected ZIP/RAR file that you have permission to crack

### Install John the Ripper
```bash
sudo apt update
sudo apt install john
```

### Convert ZIP or RAR to John Format
John the Ripper requires the password hash to be in a specific format. To convert the ZIP/RAR file’s password hash into the appropriate format, use the `zip2john` or `rar2john` utility that comes with John the Ripper. Open a terminal and navigate to the directory containing the ZIP or RAR file. Run the following command:

```bash
# for zip file
zip2john your_file.zip > zip.hash

# for rar file
rar2john your_file.rar > rar.hash
```

### Start Password Cracking
With the password hash extracted and saved, you can now initiate the password cracking process using John the Ripper. In the terminal, run the following command:

```bash
# for zip
john zip.hash

# for rar
john rar.hash
```



